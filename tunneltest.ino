// sketch to create outbound ssh connection to a fixed server, log in
// there and tunnel connections back to a fixed endpoint on the local network

// TODO use config values for settings
// TODO switch from async tcp to sync


#include <mywifi.h>
#include <AsyncTCP.h>
#include "time.h"
#include <WiFiUdp.h>
#include <mysyslog.h>
#include "mytime.h"
#include <mywebserver.h>
#include <webupdater.h>
#include <map>
#include "esp_vfs_eventfd.h"

// links
// Simple example https://github.com/rofl0r/libssh/blob/master/examples/sample.c
// Example https://github.com/me-no-dev/ESPAsyncTCP/blob/master/examples/ClientServer/Client/Client.ino
// libSSH examples: https://git.libssh.org/projects/libssh.git/tree/examples
// libSSH https://api.libssh.org/stable/
// libSSH tutorial https://api.libssh.org/stable/libssh_tutorial.html
// libSSH-ESP32 examples https://github.com/ewpa/LibSSH-ESP32/tree/master/examples

// Stack size needed to run SSH and the command parser.
const unsigned int configSTACK = 51200;
// Include the Arduino library.
#include "libssh_esp32.h"

#include <libssh/libssh.h>

// max number of concurrent connections
#define MAX_CONNS 10
// user name to log in with
//#define REMOTEUSER "username"
// server to connect to
//#define REMOTETARGET "192.168.1.1"
// port to listen to on remote server to tunnel connections back
//#define REMOTEPORT 8888
// where to forward remote connections to
//#define LOCALTARGET "192.168.1.2"
//#define LOCALPORT 80
// set to expected public key to verify server authenticity
// leave undefined to skip verification
//#define EXPECTEDKEY "192.168.1.1 AAAA....=="
// set to define private key to log in with
// leave undefined to not use private key authentication
//#define PRIVATEKEY "yyy"
// set to define password to log in with
// leave undefined to not use password authentication
//#define PASSWORD "password"
#include "secretstuff.h"

// eventfd configuration - we only need a single eventfd
static esp_vfs_eventfd_config_t eventfd_config = {
    max_fds: 1
};
static int local_data_ready = -1;
static QueueHandle_t local_messages;

static void webpage(AsyncWebServerRequest *request) {
    AsyncWebServerResponse *response = nullptr;
    int rc = 200;
    String z = "OK";
    response = request->beginResponse(rc, "text/plain", z);
    response->addHeader("Connection", "close");
    request->send(response);
}

ssh_key my_pkey = NULL;

static void tunnel_task (void *)
{
    while (true) {
        time_t then = time(NULL);
        run_tunnel();
        time_t now = time(NULL);
        time_t diff = now - then;
        if (diff < 30) {
            // rate limit connection attempts to 1 every 30s
            Serial.printf("Rate limit sleeps for %ds\n",30-diff);
            delay(1000 * (30 - diff));
        }
    }
}

/////////////////////////////////////////////////////////

struct ssh_knownhosts_entry *expected_key = NULL;

bool load_server_pubkey(ssh_session session)
{
    bool ret = false;
#ifdef EXPECTEDKEY
    int rc = ssh_known_hosts_parse_line(NULL,
                                    EXPECTEDKEY,
                                    &expected_key);
    if (rc != SSH_OK) {
        syslogf("Failed to parse known host line %d",rc);
    } else {
        syslogf("Loaded remote server expected public key ok");
        ret = true;
    }

#else
    ret = true;
#endif

    return ret;
}

bool verify_knownhost(ssh_session session)
{
    bool rc = false;
#ifdef EXPECTEDKEY
    if (expected_key == NULL) {
        syslogf("No valid expected public key");
        return false;
    }

    ssh_key srv_pubkey;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        syslogf("Failed to retrieve server public key");
        return false;
    }

    int cmp = ssh_key_cmp(srv_pubkey, expected_key->publickey, SSH_KEY_CMP_PUBLIC);
    if (cmp == 0) {
        // hash is correct
        rc = true;
        syslogf("Host key for server is correct");
    } else {
        syslogf("Host key for server is wrong");
    }
    ssh_key_free(srv_pubkey);

#else
    rc = true;
#endif

    return rc;
}

bool authenticate(ssh_session session)

{
    int method;
    char *banner;
    int rc;

    // Try to authenticate to get the list of supported types
    rc = ssh_userauth_none(session, NULL);
    if (rc == SSH_AUTH_SUCCESS) {
        // no auth required, we are in
        syslogf("Authentication succeeded using type none");
        return true;
    }
    if (rc == SSH_AUTH_ERROR) {
        // failed to get the list of supported auth types
        syslogf("Error while null authenticating : %s",ssh_get_error(session));
        return false;
    }

    // grab the supported types
    method = ssh_userauth_list(session, NULL);
    syslogf("Supported auth types %x",method);

#ifdef PRIVATEKEY
    // Try to authenticate with public key first
    if (method & SSH_AUTH_METHOD_PUBLICKEY) {
        syslogf("Attempting public key authentication");
        rc = ssh_userauth_publickey(session, NULL, my_pkey);
        if (rc == SSH_AUTH_SUCCESS) {
            syslogf("Authentication succeeded using type publickey");
            return true;
        }
    }
#endif

#ifdef PASSWORD
    const char * password = PASSWORD;
    // Try to authenticate with password
    if (method & SSH_AUTH_METHOD_PASSWORD) {
        syslogf("Attempting password authentication");
        rc = ssh_userauth_password(session, NULL, password);
        if (rc == SSH_AUTH_SUCCESS) {
            syslogf("Authentication succeeded using type password");
            return true;
        }
    }
#endif

    if (rc == SSH_AUTH_ERROR) {
        syslogf("Error while authenticating : %s",ssh_get_error(session));
    } else if (rc == SSH_AUTH_DENIED) {
        syslogf("Authentication denied");
    } else {
        syslogf("Auth error %d",rc);
    }
    return false;
}

ssh_session connect_ssh(const char *host, const char *user,int verbosity){
    ssh_session session;
    int auth=0;

    session=ssh_new();
    if (session == NULL) {
        syslogf("Failed to create new ssh object");
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
        ssh_free(session);
        syslogf("Failed to set user option on ssh object");
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        ssh_free(session);
        syslogf("Failed to set host option on ssh object");
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity)) {
        ssh_free(session);
        syslogf("Failed to set log option on ssh object");
        return NULL;
    }

    if(ssh_connect(session) != 0){
        syslogf("Connection failed : %s",ssh_get_error(session));
    } else if(!verify_knownhost(session)){
        // logged elsewhere
    } else if (authenticate(session)){
        syslogf("SSH connection succeeded");
        return session;
    }

    ssh_disconnect(session);
    ssh_free(session);
    return NULL;
}

// main entry point for running the tunnel
void run_tunnel() {
    ssh_session session;
    if (load_server_pubkey(session) == false) {
        syslogf("Failed to load server public key");
    }

    // create outbound session
    session = connect_ssh(REMOTETARGET, REMOTEUSER, 0);
    if (session == NULL) {
        return;
    }

    // only returns on failure or disconnect
    run_tunnel2(session);

    ssh_disconnect(session);
    ssh_free(session);
}

static void asynctcp_onDisconnect(void* arg, AsyncClient* client);
static void asynctcp_onConnect(void* arg, AsyncClient* client);
static void asynctcp_handleData(void* arg, AsyncClient* client, void *data, size_t len);

class myconn {
    private:
        ssh_channel m_remote;
        AsyncClient m_local;
        time_t m_lasttime;
        bool m_remote_connected;
        bool m_local_connected;
        bool m_shutdown;
        bool m_close_remote;
    public:
        myconn(ssh_channel ch) {
            Serial.printf("myconn %p opening\n", this);

            // set up member variables
            m_remote = ch;
            m_lasttime = 0;
            m_remote_connected = true;
            m_local_connected = false;
            m_close_remote = false;
            m_shutdown = false;

            // set up the callbacks
            m_local.onData(&asynctcp_handleData, this);
            m_local.onConnect(&asynctcp_onConnect, this);
            m_local.onDisconnect(&asynctcp_onDisconnect, this);

            // start the connection going - must be last thing
            m_local.connect(LOCALTARGET, LOCALPORT);
        }
        ~myconn() {
            Serial.printf("myconn %p deleted\n", this);
        }

        bool isShutdown() { return m_shutdown; }
        bool isLocalConnected() { return m_local_connected; }
        bool needCloseRemote() { bool r = m_close_remote; m_close_remote = false; return r; }

        // cleanly tear the connection down
        void doShutdown() {
            Serial.printf("myconn %p closing\n", this);
            if (m_remote_connected) {
                m_remote_connected = false;
                m_close_remote = true;
            }
            if (m_local_connected) {
                m_local_connected = false;
                m_local.close();
            }
            // wait for the close to complete before marking as shut down
        }

        void handleDataSync(void *data, size_t len) {
            Serial.printf("myconn %p processing %d bytes\n", this, len);
            //Serial.write((uint8_t*)data, len);
            if (m_remote_connected) {
                ssh_channel_write(m_remote,data,len);
            }
            m_lasttime = time(NULL);
        }

        void handleConnectSync() {
            Serial.printf("myconn %p connected to %s on port %d \n", this, LOCALTARGET, LOCALPORT);
            m_lasttime = time(NULL);
            m_local_connected = true;
        }

        void handleDisconnectSync() {
            Serial.printf("myconn %p handle disconnect\n", this);
            m_local_connected = false;
            m_shutdown = true;
            // forward the disconnect to the ssh side
            if (m_remote_connected) {
                m_close_remote = true;
            }
        }

        // ssh has some data to tunnel
        bool write(void * data, size_t len) {
            // TODO check for buffer space
            m_lasttime = time(NULL);
            if (m_local_connected) {
                Serial.printf("myconn %p sending %d bytes\n",this,len);
                m_local.add(reinterpret_cast<const char *>(data), len);
                m_local.send();
                return true;
            } else {
                Serial.printf("myconn %p cannot send %d bytes",this,len);
                return false;
            }
        }
        bool check_timeout() {
            // can only time out after connected
            if ((m_lasttime != 0) && ((time(NULL) - m_lasttime) > 60)) {
                Serial.printf("myconn %p timed out\n",this);
                return true;
            }
            return false;
        }
};

class local_message {
    public:
        typedef enum msgtype { e_local_connected, e_local_closed, e_local_rx } ;
    private:
        myconn * m_conn;
        msgtype m_type;
        void * m_data;
        size_t m_len;
    public:
        local_message(myconn * a_conn, msgtype a_type) :
            m_conn(a_conn),
            m_type(a_type),
            m_data(NULL),
            m_len(0) {};
        local_message(myconn * a_conn, void * a_data, size_t a_len) :
            m_conn(a_conn),
            m_type(e_local_rx)
        {
            // take a copy of the data
            m_data = malloc(a_len);
            m_len = a_len;
            memcpy(m_data, a_data, a_len);
        };
        ~local_message() {
            if (m_data) {
                delete m_data;
            }
        }
        void dispatch() {
            // process the message
            Serial.printf("myconn %p handling message type %d\n",m_conn,m_type);
            switch (m_type) {
                case e_local_connected:
                    m_conn->handleConnectSync();
                    break;
                case e_local_closed:
                    m_conn->handleDisconnectSync();
                    break;
                case e_local_rx:
                    m_conn->handleDataSync(m_data,m_len);
                    break;
            }
        }
};

// prototype needed to avoid arduino compiler bugs
static bool send_message(local_message * m);
static bool send_message(local_message * m) {
    // enqueue message
    xQueueSend(local_messages, &m, 100);
    // signal main thread
    uint64_t n = 1;
    size_t x = write(local_data_ready, &n, sizeof(n));
    Serial.printf("Wrote message %p, %d in queue, eventfd wrote %d\n",m,uxQueueMessagesWaiting(local_messages),x);
    return (x == sizeof(n));
}

// asynctcp callback with data to tunnel
static void asynctcp_handleData(void* arg, AsyncClient* client, void *data, size_t len) {
    myconn * c = reinterpret_cast<myconn*>(arg);
    Serial.printf("myconn %p received %d bytes\n", c, len);
    //Serial.write((uint8_t*)data, len);
    send_message(new local_message(c, data, len));
}
// asynctcp callback, connection established
static void asynctcp_onConnect(void* arg, AsyncClient* client) {
    myconn * c = reinterpret_cast<myconn*>(arg);
    Serial.printf("myconn %p connected\n",c);
    send_message(new local_message(c, local_message::e_local_connected));
}
// asynctcp callback, forwarded connection disconnected from us
static void asynctcp_onDisconnect(void* arg, AsyncClient* client) {
    myconn * c = reinterpret_cast<myconn*>(arg);
    Serial.printf("myconn %p disconnected\n", c);
    send_message(new local_message(c, local_message::e_local_closed));
}

// we got an outbound connection with its reverse tunnel
// wait for tunnelled connections and run them
void run_tunnel2(ssh_session & session) {

    ssh_channel channel;
    char buffer[256];
    int rbytes, wbytes, total = 0;
    int rc;
    struct timeval tmo;

    // create the reverse tunnel
    rc = ssh_channel_listen_forward(session, NULL, REMOTEPORT, NULL);
    if (rc != SSH_OK)
    {
        syslogf("Error opening remote port: %s", ssh_get_error(session));
        return;
    }

    // the set of connections
    std::map<ssh_channel,myconn *> conn_list;

    while (ssh_is_connected(session)) {
        int timeout = 0;
        if (conn_list.empty()) {
            timeout = 60000;
        }

        // do not permit more than max connections
        if (conn_list.size() < MAX_CONNS) {
            Serial.printf("Checking for new connections for %d\n",timeout);
            channel = ssh_channel_accept_forward(session, timeout, NULL);
            if (channel != NULL) {
                // got incoming connection
                Serial.printf("Got new connection channel %p\n",channel);
                conn_list[channel] = new myconn(channel);
            } else if (conn_list.empty()) {
                // no connected channels, go round the loop again
                continue;
            }
        }
     
        // wait for something to happen
        fd_set fds;
        int maxfd;
        int k = ssh_get_fd(session);
        FD_ZERO(&fds);
        FD_SET(k, &fds);
        FD_SET(local_data_ready, &fds);
        maxfd = 1+std::max(k,local_data_ready);

        // wait for max 1 sec before checking for timeouts
        tmo.tv_sec = 1; tmo.tv_usec = 0;

        // find the connections with data
        // TODO fix: if local never connects we never check the ssh side to see if it closes
        Serial.printf("0 maxfd %d sshfd %d ldr %d\n",maxfd,k,local_data_ready);
        rc = select(maxfd, &fds, NULL, NULL, &tmo);
        Serial.printf("1 rc %d\n",rc);

        // some data has come in from the local side
        if (FD_ISSET(local_data_ready, &fds)) {
            // clear the eventfd
            uint64_t n;
            read(local_data_ready, &n, sizeof(n));
            Serial.printf("Processing %d messages\n",uxQueueMessagesWaiting(local_messages));

            // process the local data queue
            local_message * m;
            while (xQueueReceive(local_messages, &m, 0) == pdTRUE) {
                Serial.printf("Processing message %p\n",m);
                m->dispatch();
                delete(m);
            }
        }

        if (!FD_ISSET(ssh_get_fd(session),&fds)) {
            // TODO see if ssh fd ever fires
            // nothing waiting for the ssh side so continue round the loop
            Serial.printf("ssh not ready\n");
            //continue;
        } else {
            Serial.printf("kick ssh\n");
            ssh_set_fd_toread(session);
        }

        // TODO handle errors

        // build list of connections to watch
        // tidy any existing closures
        std::map<ssh_channel,myconn *>::const_iterator j = conn_list.begin();

        while (j != conn_list.end()) {
            if (!ssh_channel_is_open(j->first)) {
                // likely local closed on us, async has closed the ssh channel
                // so we are just tidying up here
                Serial.printf("Channel %p has closed\n",j->second);
                if (j->second->isShutdown()) {
                    // forwarding side has also gone
                    delete j->second;
                    ssh_channel_free(j->first);
                    conn_list.erase(j++);
                    Serial.printf("Connection channel %p is now gone\n",j->first);
                } else {
                    Serial.printf("Channel %p closing local\n",j->second);
                    // must tell the forwarding side to go away
                    j->second->doShutdown();
                    // leave the object in place until it has shut down
                    ++j;
                }
            } else if (j->second->check_timeout()) {
                // channel has timed out, close it
                Serial.printf("Channel %p has timed out\n",j->second);
                j->second->doShutdown();
                ++j;
            } else if (j->second->needCloseRemote()) {
                // local has gone away and we must close the remote side
                Serial.printf("Channel %p closing remote\n",j->second);
                ssh_channel_send_eof(j->first);
                ssh_channel_close(j->first);
                ++j;
            } else if (!j->second->isLocalConnected()) {
                // channel is active but local is not yet connected so skip this time around
                Serial.printf("Channel %p not connected\n",j->second);
                ++j;
            } else {
                // channel is still active
                // run connection until no more data
                int len;
                while (1) {
                    len=ssh_channel_read_timeout(j->first,buffer,sizeof(buffer),0,0);
                    Serial.printf("Channel %p read %d\n",j->first,len);
                    if(len==-1){
                        // drop out of the loop when not readable
                        Serial.printf("Error reading channel %p: %s\n", j->second, ssh_get_error(session));
                        break;
                    } else if (len > 0) {
                        // have some data, send to local
                        if (!j->second->write(buffer,len)) {
                            Serial.printf("Write failure on channel %p\n", j->second);
                            // error occurred, close the connection
                            j->second->doShutdown();
                            break;
                        }
                    } else if (ssh_channel_is_eof(j->first)) {
                        Serial.printf("EOF on channel %p\n", j->second);
                        j->second->doShutdown();
                        break;
                    } else {
                        // no data received
                        break;
                    }
                }
                ++j;
            }
        } // end of running a connection

    } // end of session still active

    // close local connections
    Serial.printf("Session closed, closing %d connections\n",conn_list.size());
    std::map<ssh_channel,myconn *>::const_iterator j = conn_list.begin();
    while (j != conn_list.end()) {
        // close everything as required
        j->second->doShutdown();
        ++j;
    }
    delay(1000);
    while (conn_list.begin() != conn_list.end()) {
        // deleting the connection will close the ssh channel
        delete conn_list.begin()->second;
        ssh_channel_free(conn_list.begin()->first);
        conn_list.erase(conn_list.begin());
    }
}

void setup() {
    // Serial port for debugging purposes
    Serial.begin(115200);
    WIFI_init("tunneltest",true);
    SyslogInit("tunneltest");
    WS_init("tunneltest");
    UD_init(server);
    server.on("/tunneltest", HTTP_GET, webpage);

    // set up eventfd for waking the foreground task to deal with
    // data received on the async tcp side
    esp_vfs_eventfd_register(&eventfd_config);
    local_data_ready = eventfd(0,0 /*EFD_SUPPORT_ISR*/);
    local_messages = xQueueCreate(20,sizeof(local_message*));

    // Initialize the Arduino library.
    libssh_begin();

#ifdef PRIVATEKEY
    // key needs to start with 
    // "-----BEGIN OPENSSH PRIVATE KEY-----"
    // or
    // "-----BEGIN RSA PRIVATE KEY-----"
    // PRIVATEKEY holds key to log in with
    int rc = ssh_pki_import_privkey_base64(
        PRIVATEKEY, // base64 encoded private key
        NULL,       // key passphrase
        NULL,       // no custom auth function
        NULL,       // no custom auth data
        &my_pkey);

    if (rc != SSH_OK || my_pkey == NULL) {
        Serial.printf("Failed to import public key %d\n",rc);
        syslogf("Failed to import public key %d",rc);
    }
#endif

    // TODO run task
    // Stack size needs to be larger, so continue in a new task.
    //xTaskCreatePinnedToCore(tunnel_task, "tunnel", configSTACK, NULL, (tskIDLE_PRIORITY + 3), NULL, portNUM_PROCESSORS - 1);
    xTaskCreate(tunnel_task, "tunnel", configSTACK, NULL, 1, NULL);
}

void loop() {
  // put your main code here, to run repeatedly:

  // TODO if not connect and wifi is connected then reconnect
}


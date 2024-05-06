// sketch to create outbound ssh connection to a fixed server, log in
// there and tunnel connections back to a fixed endpoint on the local network
#include <mywifi.h>
#include <AsyncTCP.h>
#include "time.h"
#include <WiFiUdp.h>
#include <mysyslog.h>
#include "mytime.h"
#include <mywebserver.h>
#include <webupdater.h>
#include <LittleFS.h>
#include <map>

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
#define REMOTEUSER "username"
// server to connect to
#define REMOTETARGET "servername.example.com"
// port to listen to on remote server to tunnel connections back
#define REMOTEPORT 8888
// where to forward remote connections to
#define LOCALTARGET "127.0.0.1"
#define LOCALPORT 80
// set to expected public key to verify server authenticity
// leave undefined to skip verification
#define EXPECTEDKEY "xxx"
// set to define private key to log in with
// leave undefined to not use private key authentication
#define PRIVATEKEY "yyy"
// set to define password to log in with
// leave undefined to not use password authentication
#define PASSWORD "Password123"


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

void setup() {
    // Serial port for debugging purposes
    Serial.begin(115200);
    WIFI_init("tunneltest",true);
    WS_init("tunneltest");
    UD_init(server);
    server.on("/tunneltest", HTTP_GET, webpage);

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
        return false;
    }

    int cmp = ssh_key_cmp(srv_pubkey, expected_key->publickey, SSH_KEY_CMP_PUBLIC);
    if (cmp == 0) {
        // hash is correct
        rc = true;
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
        return true;
    }
    if (rc == SSH_AUTH_ERROR) {
        // failed to get the list of supported auth types
        syslogf("Error while null authenticating : %s",ssh_get_error(session));
        return false;
    }

    // grab the supported types
    method = ssh_userauth_list(session, NULL);

#ifdef PRIVATEKEY
    // Try to authenticate with public key first
    if (method & SSH_AUTH_METHOD_PUBLICKEY) {
        rc = ssh_userauth_publickey(session, NULL, my_pkey);
        if (rc == SSH_AUTH_SUCCESS) {
            return true;
        }
    }
#endif

#ifdef PASSWORD
    const char * password = PASSWORD;
    // Try to authenticate with password
    if (method & SSH_AUTH_METHOD_PASSWORD) {
        rc = ssh_userauth_password(session, NULL, password);
        if (rc == SSH_AUTH_SUCCESS) {
            return true;
        }
    }
#endif

    if (rc == SSH_AUTH_ERROR) {
        syslogf("Error while authenticating : %s",ssh_get_error(session));
    } else if (rc == SSH_AUTH_DENIED) {
        syslogf("Authentication denied");
    }
    return false;
}

ssh_session connect_ssh(const char *host, const char *user,int verbosity){
    ssh_session session;
    int auth=0;

    session=ssh_new();
    if (session == NULL) {
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0) {
        ssh_free(session);
        return NULL;
    }

    if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0) {
        ssh_free(session);
        return NULL;
    }

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    if(ssh_connect(session) != 0){
        syslogf("Connection failed : %s",ssh_get_error(session));
    } else if(!verify_knownhost(session)){
        // logged elsewhere
    } else if (authenticate(session)){
        return session;
    }

    ssh_disconnect(session);
    ssh_free(session);
    return NULL;
}

// main entry point for running the tunnel
void run_tunnel() {
    ssh_session session;
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


class myconn {
    private:
        ssh_channel m_remote;
        AsyncClient m_local;
        time_t m_lasttime;
        bool m_remote_connected;
        bool m_local_connected;
    public:
        myconn(ssh_channel ch) {
            m_local.onData(&myconn::handleData, this);
            m_local.onConnect(&myconn::onConnect, this);
            m_local.onDisconnect(&myconn::onDisconnect, this);
            m_local.connect(LOCALTARGET, LOCALPORT);
            m_remote = ch;
            m_lasttime = 0;
            m_remote_connected = true;
            Serial.printf("myconn %p opening\n", this);
        }
        ~myconn() {
            Serial.printf("myconn %p closing\n", this);
            if (m_local_connected) {
                m_local_connected = false;
                m_local.close();
            }
            if (m_remote_connected) {
                m_remote_connected = false;
                // TODO something less brutal than free
                //ssh_channel_close(m_remote);
                ssh_channel_free(m_remote);
            }
            // TODO do we need to wait for the close to complete?
        }

        // asynctcp callback with data to tunnel
        static void handleData(void* arg, AsyncClient* client, void *data, size_t len) {
            myconn * c = reinterpret_cast<myconn*>(arg);
            Serial.printf("myconn %p received %d bytes\n", c, len);
            //Serial.write((uint8_t*)data, len);
            if (c->m_remote_connected) {
                ssh_channel_write(c->m_remote,data,len);
            }
            c->m_lasttime = time(NULL);
        }

        // asynctcp callback, connection established
        static void onConnect(void* arg, AsyncClient* client) {
            myconn * c = reinterpret_cast<myconn*>(arg);
            Serial.printf("myconn %p connected to %s on port %d \n", c, LOCALTARGET, LOCALPORT);
            c->m_lasttime = time(NULL);
            c->m_local_connected = true;
        }

        static void onDisconnect(void* arg, AsyncClient* client) {
            myconn * c = reinterpret_cast<myconn*>(arg);
            Serial.printf("myconn %p disconnected\n", c);
            c->m_local_connected = false;
            // forward the disconnect to the ssh side
            if (c->m_remote_connected) {
                ssh_channel_send_eof(c->m_remote);
                // TODO something less brutal than free
                //ssh_channel_close(c->m_remote);
                ssh_channel_free(c->m_remote);
            }
        }
        // ssh has some data to tunnel
        bool write(void * data, size_t len) {
            // TODO check for buffer space
            m_lasttime = time(NULL);
            if (m_local_connected) {
                Serial.printf("myconn %p sending %d bytes",this,len);
                m_local.add(reinterpret_cast<const char *>(data), len);
                m_local.send();
                return true;
            } else {
                Serial.printf("myconn %p cannot send %d bytes",this,len);
                return false;
            }
        }
        bool check_timeout() {
            if ((time(NULL) - m_lasttime) > 60) {
                Serial.printf("myconn %p timed out",this);
                return true;
            }
            return false;
        }
};

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
    // buffer to pass to select
    ssh_channel channels[MAX_CONNS+1];

    while (ssh_is_connected(session)) {
        int timeout = 0;
        if (conn_list.empty()) {
            timeout = 60000;
        }

        // do not permit more than max connections
        if (conn_list.size() < MAX_CONNS) {
            channel = ssh_channel_accept_forward(session, timeout, NULL);
            if (channel != NULL) {
                // got incoming connection
                Serial.printf("Got new connection %p\n",channel);
                conn_list[channel] = new myconn(channel);
            } else if (conn_list.empty()) {
                // no connected channels, go round the loop again
                continue;
            }
        }
     
        // the business end

        // TODO blocking writes
        // TODO errors
        // TODO races/threading upon deletion

        // wait for max 1 sec before checking for timeouts
        tmo.tv_sec = 1; tmo.tv_usec = 0;

        // build list of connections to watch
        // tidy any existing closures
        int i=0;
        std::map<ssh_channel,myconn *>::const_iterator j = conn_list.begin();

        while ((i < MAX_CONNS) && (j != conn_list.end())) {
            if (!ssh_channel_is_open(j->first)) {
                // likely local closed on us, async has closed the ssh channel
                // so we are just tidying up here
                Serial.printf("Channel %p has closed\n",j->second);
                delete j->second;
                conn_list.erase(j++);
            } else if (j->second->check_timeout()) {
                // channel has timed out, close it
                Serial.printf("Channel %p has timed out\n",j->second);

                // the delete will close both sides
                delete j->second;
                conn_list.erase(j++);
            } else {
                // wait for some data
                channels[i++] = j->first;
                ++j;
            }
        }

        // if there are any active connections to run...
        if (i > 0) {
            // find the connections with data
            channels[i] = NULL;
            rc = ssh_channel_select(channels,NULL,NULL,&tmo);
            // check each connection reported by select
            while (--i >= 0) {
                if (channels[i] != NULL) {
                    // run connection until block
                    while(channels[i] && ssh_channel_is_open(channels[i]) && ssh_channel_poll(channels[i],0)>0){
                        int len=ssh_channel_read(channels[i],buffer,sizeof(buffer),0);
                        if(len==-1){
                            // drop out of the loop when not readable
                            Serial.printf("Error reading channel %d %p: %s\n", i, conn_list[channels[i]], ssh_get_error(session));
                            break;
                        } else if(len==0){
                            Serial.printf("EOF on channel %d %p %d\n", i, conn_list[channels[i]],ssh_channel_get_exit_status(channel));
                            delete conn_list[channels[i]];
                            conn_list.erase(channels[i]);
                            // the delete will free the channel
                            // TODO synchronise the channel free
                            //ssh_channel_free(channels[i]);
                            break;
                        } else {
                            // have some data, send to local
                            if (!conn_list[channels[i]]->write(buffer,len)) {
                                Serial.printf("Write failure on channel %d %p\n", i, conn_list[channels[i]]);
                                // error occurred, close the connection
                                delete conn_list[channels[i]];
                                conn_list.erase(channels[i]);
                                break;
                            }
                        }
                    }
                }
            } // end of running a connection

        } // end of >0 connections active

    } // end of session still active

    // TODO close local connections
    Serial.printf("Session closed, closing connections\n");
    while (conn_list.begin() != conn_list.end()) {
        // deleting the connection will close the ssh channel
        delete conn_list.begin()->second;
        conn_list.erase(conn_list.begin());
    }
}

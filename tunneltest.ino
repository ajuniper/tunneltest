// sketch to create outbound ssh connection to a fixed server, log in
// there and tunnel connections back to a fixed endpoint on the local network

// TODO use config values for settings

#include <mywifi.h>
#include "time.h"
#include <WiFiUdp.h>
#include <mysyslog.h>
#include "mytime.h"
#include <mywebserver.h>
#include <webupdater.h>
#include <map>
#include "esp_vfs_eventfd.h"
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

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

#if 1
#define DEBUG(__x...) Serial.printf(__x)
#else
#define DEBUG(__x...)
#endif

// the address structure that we will connect to
struct addrinfo s_hints = { .ai_socktype = SOCK_STREAM };
struct addrinfo *s_target;

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
            DEBUG("Rate limit sleeps for %ds\n",30-diff);
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

class myconn {
    private:
        ssh_channel m_remote;
        int m_local; // socket
        time_t m_lasttime;
        bool m_remote_connected;
        bool m_local_connected;
        bool m_shutdown;
    public:
        myconn(ssh_channel ch) {
            DEBUG("myconn %p opening\n", this);

            // set up member variables
            m_remote = ch;
            m_lasttime = 0;
            m_remote_connected = true;
            m_local_connected = false;
            bool l_close_remote = true; // assume failure
            m_shutdown = false;

            // connect our socket
            m_local = socket(s_target->ai_family, s_target->ai_socktype, s_target->ai_protocol);
            if (m_local < 0) {
                DEBUG("myconn %p failed to create socket, error %d\n",this,errno);
            } else if (fcntl(m_local, F_SETFL, fcntl(m_local, F_GETFL) | O_NONBLOCK) == -1) {
                DEBUG("myconn %p unable to set socket non blocking, error %d\n",this,errno);
                close(m_local);
                m_local = -1;
            } else if (connect(m_local, s_target->ai_addr, s_target->ai_addrlen) == 0) {
                // socket is connected
                DEBUG("myconn %p connected %d\n",this,m_local);
                m_local_connected = true;
                l_close_remote = false;
            } else if ((errno == EAGAIN) || (errno == EINPROGRESS)) {
                // socket is pending connection
                DEBUG("myconn %p waiting for connection to complete %d\n",this,m_local);
                l_close_remote = false;
            } else {
                DEBUG("myconn %p failed to connect, errno %d\n",this,errno);
                syslogf("onwards failed to connect, errno %d",errno);
                close(m_local);
                m_local = -1;
            }
            if (l_close_remote) {
                closeRemote();
            }
        }
        ~myconn() {
            DEBUG("myconn %p deleted\n", this);
        }

        bool isShutdown() { return m_shutdown; }
        bool isLocalConnected() { return m_local_connected; }
        int getFd() { return m_local; }

        void closeRemote() {
            if (m_remote_connected) {
                m_remote_connected = false;
                ssh_channel_send_eof(m_remote);
                ssh_channel_close(m_remote);
            }
        }

        // cleanly tear the connection down
        void doShutdown() {
            DEBUG("myconn %p closing\n", this);
            closeRemote();
            if (m_local_connected) {
                m_local_connected = false;
                int r = close(m_local);
                if (r != 0) {
                    DEBUG("myconn %p failed to close, errno %d\n",errno);
                }
                m_local = -1;
                m_shutdown = true;
            }
            // wait for the close to complete before marking as shut down
        }

        void handleRead() {
            DEBUG("myconn %p processing read\n", this);
            uint8_t buf[512];
            int len;
            while (1) {
                len = read(m_local, buf, 512);
                DEBUG("myconn %p read %d bytes\n",this,len);
                if (len > 0) {
                    //Serial.write((uint8_t*)data, len);
                    if (m_remote_connected) {
                        ssh_channel_write(m_remote,buf,len);
                    }
                } else if ((len < 0) && (errno == EAGAIN)) {
                    // no more data
                    break;
                } else {
                    // connection closed
                    DEBUG("myconn %p read error %d\n",errno);
                    doShutdown();
                    break;
                }
            }
            m_lasttime = time(NULL);
        }

        void handleWrite() {
            // writable is only used to detect that the socket connected
            int sockerr;
            socklen_t len = (socklen_t)sizeof(int);
            if (getsockopt(m_local, SOL_SOCKET, SO_ERROR, (void*)(&sockerr), &len) < 0) {
                DEBUG("myconn %p failed to get socket status, %d\n",this,errno);
                doShutdown();
            } else if (sockerr) {
                DEBUG("myconn %p failed to connect, erno %d\n",sockerr);
                syslogf("onward connection failed to connect, %d",sockerr);
                doShutdown();
            } else {
                DEBUG("myconn %p connected to %s on port %d \n", this, LOCALTARGET, LOCALPORT);
                m_lasttime = time(NULL);
                m_local_connected = true;
            }
        }

        void handleError() {
            DEBUG("myconn %p handle error\n", this);
            doShutdown();
        }

        // ssh has some data to tunnel
        bool write(void * data, size_t len) {
            m_lasttime = time(NULL);
            if (m_local_connected) {
                DEBUG("myconn %p sending %d bytes\n",this,len);
                while (len > 0) {
                    int lw = ::write(m_local,data,len);
                    if (lw == len) {
                        // all written ok
                        break;
                    } else if (lw > 0) {
                        DEBUG("myconn %p only sent %d bytes, errno %d\n",this,lw,errno);
                        len -= lw;
                        data += lw;
                        delay(10);
                        // go round the loop again
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        delay(10);
                        // go round the loop again
                    } else {
                        DEBUG("myconn %p write error %d\n",this,errno);
                        return false;
                    }
                } // end looping over all data
                return true;
            } else {
                DEBUG("myconn %p cannot send %d bytes",this,len);
                return false;
            }
        }
        bool check_timeout() {
            // can only time out after connected
            if ((m_lasttime != 0) && ((time(NULL) - m_lasttime) > 60)) {
                DEBUG("myconn %p timed out\n",this);
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

    while (ssh_is_connected(session)) {
        int timeout = 0;
        if (conn_list.empty()) {
            timeout = 60000;
        }

        // do not permit more than max connections
        if (conn_list.size() < MAX_CONNS) {
            DEBUG("Checking for new connections for %d\n",timeout);
            channel = ssh_channel_accept_forward(session, timeout, NULL);
            if (channel != NULL) {
                // got incoming connection
                DEBUG("Got new connection channel %p\n",channel);
                conn_list[channel] = new myconn(channel);
            } else if (conn_list.empty()) {
                // no connected channels, go round the loop again
                continue;
            }
        }
     
        // wait for something to happen
        // TODO use fde to spot errors
        fd_set fde,fdw, fdr;
        int maxfd;
        int k = ssh_get_fd(session);
        DEBUG("ssh fd %d\n",k);
        FD_ZERO(&fde);
        FD_ZERO(&fdr);
        FD_ZERO(&fdw);
        //FD_SET(k, &fde);
        FD_SET(k, &fdr);
        //FD_SET(k, &fdw);
        maxfd = k;
        std::map<ssh_channel,myconn *>::const_iterator j = conn_list.begin();
        while (j != conn_list.end()) {
            k = j->second->getFd();
            if (k >= 0) {
                maxfd = std::max(k,maxfd);
                //FD_SET(k, &fde);
                if (j->second->isLocalConnected()) {
                    FD_SET(k, &fdr);
                } else {
                    FD_SET(k, &fdw);
                }
            }
            ++j;
        }

        // wait for max 1 sec before checking for timeouts
        tmo.tv_sec = 1; tmo.tv_usec = 0;

        // find the connections with data
        DEBUG("0 maxfd %d\n",maxfd);
        rc = select(maxfd+1, &fdr, &fdw, &fde, &tmo);
        DEBUG("1 rc %d\n",rc);
        DEBUG("readable: ");
        for (k=0; k<=maxfd; ++k) { if (FD_ISSET(k,&fdr)) { DEBUG("%d ",k); } } ; DEBUG("\n");
        DEBUG("writable: ");
        for (k=0; k<=maxfd; ++k) { if (FD_ISSET(k,&fdw)) { DEBUG("%d ",k); } } ; DEBUG("\n");
        DEBUG("error: ");
        for (k=0; k<=maxfd; ++k) { if (FD_ISSET(k,&fde)) { DEBUG("%d ",k); } } ; DEBUG("\n");

        // has some data come in from the local side
        j = conn_list.begin();
        while (j != conn_list.end()) {
            k = j->second->getFd();
            if (k < 0) {
                // not connected
            } else if (FD_ISSET(k,&fdr)) {
                // fd is readable
                j->second->handleRead();
            } else if (FD_ISSET(k,&fdw)) {
                // fd is readable
                j->second->handleWrite();
            } else if (FD_ISSET(k,&fde)) {
                // fd has errored
                j->second->handleError();
            }
            ++j;
        }

        if (!FD_ISSET(ssh_get_fd(session),&fdr)) {
            // nothing waiting for the ssh side so continue round the loop
            DEBUG("ssh not ready\n");
            // ssh fd is not reliable enough to continue
            //continue;
        } else {
            // TODO is this necessary?
            DEBUG("kick ssh\n");
            ssh_set_fd_toread(session);
        }

        // build list of connections to watch
        // tidy any existing closures
        j = conn_list.begin();

        while (j != conn_list.end()) {
            bool closeChannel = false;
            if (!ssh_channel_is_open(j->first)) {
                // likely local closed on us, async has closed the ssh channel
                // so we are just tidying up here
                DEBUG("Channel %p has closed\n",j->second);
                closeChannel = true;
            } else if (j->second->check_timeout()) {
                // channel has timed out, close it
                DEBUG("Channel %p has timed out\n",j->second);
                closeChannel = true;
            } else if (!j->second->isLocalConnected()) {
                // channel is active but local is not yet connected so skip this time around
                DEBUG("Channel %p not connected\n",j->second);
                ++j;
            } else {
                // channel is still active
                // run connection until no more data
                int len;
                while (1) {
                    len=ssh_channel_read_timeout(j->first,buffer,sizeof(buffer),0,0);
                    DEBUG("Channel %p read %d\n",j->first,len);
                    if(len==-1){
                        // drop out of the loop when not readable
                        DEBUG("Error reading channel %p: %s\n", j->second, ssh_get_error(session));
                        break;
                    } else if (len > 0) {
                        // have some data, send to local
                        if (!j->second->write(buffer,len)) {
                            DEBUG("Write failure on channel %p\n", j->second);
                            // error occurred, close the connection
                            closeChannel = true;
                            break;
                        }
                    } else if (ssh_channel_is_eof(j->first)) {
                        DEBUG("EOF on channel %p\n", j->second);
                        closeChannel = true;
                        break;
                    } else {
                        // no data received
                        break;
                    }
                }
            }
            if (closeChannel) {
                j->second->doShutdown();
                delete j->second;
                ssh_channel_free(j->first);
                conn_list.erase(j++);
            } else {
                ++j;
            }
        } // end of running a connection

    } // end of session still active

    // close local connections
    DEBUG("Session closed, closing %d connections\n",conn_list.size());
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
        DEBUG("Failed to import public key %d\n",rc);
        syslogf("Failed to import public key %d",rc);
    }
#endif

    // look up our target details
    // only needs to be done the once
    int res;
    do {
        res = getaddrinfo(LOCALTARGET, LOCALPORT, &s_hints, &s_target);
        DEBUG("getaddrinfo returned %d\n",res);
    } while (res < 0);

    // Stack size needs to be larger, so continue in a new task.
    //xTaskCreatePinnedToCore(tunnel_task, "tunnel", configSTACK, NULL, (tskIDLE_PRIORITY + 3), NULL, portNUM_PROCESSORS - 1);
    xTaskCreate(tunnel_task, "tunnel", configSTACK, NULL, 1, NULL);
}

void loop() {
  // put your main code here, to run repeatedly:
}


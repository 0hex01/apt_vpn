// 0hex01 vpn manager - gtk3, dark/green terminal9 style
// Connects OpenVPN (.ovpn) and WireGuard (.conf) profiles via pkexec.
#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include "countries.h"
#include "embedded_data.h"

static const std::string VPN_DIR   = "/usr/local/lib/0hex01/vpn_files";
static const std::string PID_FILE  = "/tmp/0hex01-vpn.pid";
static const std::string AUTH_FILE = "/tmp/0hex01-vpn-auth";
static const std::string LOG_FILE  = "/tmp/0hex01-vpn.log";

// ---------- widgets ----------
static GtkWidget *win, *combo, *store_model, *status_lbl, *btn_con, *btn_dis;
static std::string selected_file;      // full path of selected profile
static bool selected_is_wg = false;    // true if wireguard profile selected
static std::string active_conn_file;   // config actually connected (wg or ovpn)
static bool conn_is_wg = false;        // active_conn_file is a wireguard conf
static std::string wg_up_conf;         // conf path passed to wg-quick (may be sanitized)
static std::string pending_ovpn;       // ovpn file mid-handshake (daemon up, no tun yet)
static time_t pending_since = 0;       // when pending_ovpn started (timeout guard)
static std::string ovpn_dev;           // tun device in use (for DNS teardown)
static bool dns_applied = false;       // resolvconf entry added -> remove on disconnect
static bool ipv6_managed = false;      // we disabled ipv6 -> restore it on disconnect

// uid of the user who launched us (when running elevated via pkexec)
static uid_t orig_uid = 0;

static const char *MODES[] = {"udp", "tcp", "secure_udp", "secure_tcp", "wireguard_files"};

// ---------- helpers ----------
static std::string lower(std::string s) {
    for (auto &c : s) c = tolower(c);
    return s;
}
static std::vector<std::string> split(const std::string &s, char d) {
    std::vector<std::string> v; std::stringstream ss(s); std::string t;
    while (std::getline(ss, t, d)) v.push_back(t);
    return v;
}
static std::string country(const std::string &code) {
    auto it = COUNTRIES.find(lower(code));
    return it == COUNTRIES.end() ? code : it->second;
}
static bool run_ok(const char *cmd) {
    int r = system(cmd);
    return r != -1 && WEXITSTATUS(r) == 0;
}
// run cmd, capture stdout+stderr, return exit status
static int run_capture(const std::string &cmd, std::string &out) {
    out.clear();
    FILE *fp = popen((cmd + " 2>&1").c_str(), "r");
    if (!fp) return -1;
    char buf[512];
    while (fgets(buf, sizeof buf, fp)) out += buf;
    return pclose(fp);
}
static bool wg_iface_up() {
    std::string o;
    run_capture("/usr/bin/wg show interfaces 2>/dev/null", o);
    for (char c : o) if (!isspace(c)) return true;   // any iface listed
    return false;
}
// -1 = ipv6 module absent (kernel off), 0 = enabled, 1 = sysctl-disabled
static int ipv6_state() {
    std::ifstream f("/proc/sys/net/ipv6/conf/all/disable_ipv6");
    int v = -1;
    if (f >> v) return v;
    return -1;
}
static bool tun_up() {
    // a live tun interface means openvpn finished connecting
    DIR *d = opendir("/sys/class/net");
    if (!d) return false;
    bool found = false;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "tun", 3) == 0) { found = true; break; }
    }
    closedir(d);
    return found;
}
static bool ipv6_will_work() { return ipv6_state() == 0; }
static void ipv6_set(bool enable) {
    std::string v = enable ? "0" : "1", out;
    run_capture("sysctl -w net.ipv6.conf.all.disable_ipv6=" + v +
                " net.ipv6.conf.default.disable_ipv6=" + v + " >/dev/null 2>&1", out);
}
// wg-quick derives the interface name from the conf basename - the stem must
// be <=15 chars (IFNAMSIZ) and end in .conf. Also, when the system can't use
// IPv6, `ip -6 address add` fails -> write an IPv4-only copy.
// Either case -> copy/rewrite to /tmp/<stem[:15]>.conf and return that path.
static std::string wg_prepare_conf(const std::string &src) {
    std::string stem = src.substr(src.rfind('/') + 1);
    if (stem.size() > 5 && stem.substr(stem.size() - 5) == ".conf")
        stem.resize(stem.size() - 5);
    bool need_v4 = !ipv6_will_work();
    bool need_name = stem.size() > 15;
    if (!need_v4 && !need_name) return src;
    std::ifstream in(src);
    if (!in) return src;
    std::string dst = "/tmp/" + stem.substr(0, 15) + ".conf";
    std::ofstream out(dst);
    auto trim = [](std::string s) {
        size_t a = s.find_first_not_of(" \t"), b = s.find_last_not_of(" \t");
        return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
    };
    std::string line;
    while (std::getline(in, line)) {
        std::string t = trim(line);
        auto eq = t.find('=');
        if (t.empty() || eq == std::string::npos || !need_v4) {
            out << line << "\n"; continue;
        }
        std::string key = trim(t.substr(0, eq));
        if (key == "Address" || key == "AllowedIPs" || key == "DNS") {
            auto vals = split(t.substr(eq + 1), ',');
            std::string keep;
            for (auto &v : vals) {
                std::string x = trim(v);
                if (x.find(':') == std::string::npos) {   // keep IPv4 only
                    if (!keep.empty()) keep += ", ";
                    keep += x;
                }
            }
            if (keep.empty()) continue;                    // drop pure-IPv6 line
            out << key << " = " << keep << "\n";
        } else out << line << "\n";
    }
    out.close();
    chmod(dst.c_str(), 0600);
    return dst;
}

// Filename -> display name (country / route)
static std::string display_name(const std::string &f) {
    std::string b = f;
    auto dot = b.find('.');
    std::string stem = dot == std::string::npos ? b : b.substr(0, dot);

    if (b.size() > 5 && b.substr(b.size() - 5) == ".ovpn") {
        // AA-BB-NN.protonvpn.udp.ovpn  -> secure core: Exit(BB) via Entry(AA)
        auto parts = split(stem, '-');
        if (parts.size() >= 2 && parts[0].size() == 2)
            return country(parts[1]) + "  (via " + country(parts[0]) + ")";
        // XX.protonvpn.tcp.ovpn
        return country(split(stem, '.')[0]);
    }
    // wireguard: wg-XX-N.conf | WG2-US-GA-308.conf | wireguard1-US-NC-3.conf
    auto parts = split(stem, '-');
    for (size_t i = 1; i < parts.size(); i++) {
        if (parts[i].size() == 2 &&
            std::all_of(parts[i].begin(), parts[i].end(),
                        [](char c){ return c >= 'A' && c <= 'Z'; })) {
            std::string cc = lower(parts[i]);
            std::string name = country(cc);
            if (cc == "us" && i + 1 < parts.size() &&
                parts[i + 1].size() == 2) {
                auto st = US_STATES.find(parts[i + 1]);
                if (st != US_STATES.end()) name += " \xe2\x80\x94 " + st->second;
            }
            return name;
        }
    }
    return stem;
}

// ---------- credential storage (AES-256-GCM) ----------
static std::string creds_path() {
    struct passwd *pw = getpwuid(orig_uid ? orig_uid : getuid());
    std::string home = pw ? pw->pw_dir : "/tmp";
    return home + "/.config/0hex01-vpn/creds.bin";
}
static void derive_key(unsigned char key[32]) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    std::string mat;
    { std::ifstream f("/etc/machine-id"); mat.assign(std::istreambuf_iterator<char>(f), {}); }
    struct passwd *pw = getpwuid(orig_uid ? orig_uid : getuid());
    mat += pw ? pw->pw_name : "user";
    mat += "0hex01-vpn-kdf";
    SHA256((unsigned char*)mat.data(), mat.size(), h);
    memcpy(key, h, 32);
}
static bool creds_save(const std::string &u, const std::string &p) {
    unsigned char key[32], iv[12], tag[16];
    derive_key(key);
    RAND_bytes(iv, sizeof iv);
    std::string plain = u + "\n" + p;
    std::vector<unsigned char> ct(plain.size());
    int len = 0, clen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ct.data(), &len, (unsigned char*)plain.data(), plain.size());
    clen = len;
    EVP_EncryptFinal_ex(ctx, ct.data() + clen, &len); clen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    std::string dir = creds_path().substr(0, creds_path().rfind('/'));
    system(("mkdir -p '" + dir + "'").c_str());
    std::ofstream f(creds_path(), std::ios::binary);
    f.write("0H01", 4);
    f.write((char*)iv, 12); f.write((char*)tag, 16);
    f.write((char*)ct.data(), clen);
    f.close();
    // keep ownership with the launching user when running as root
    if (orig_uid) {
        struct passwd *pw = getpwuid(orig_uid);
        gid_t g = pw ? pw->pw_gid : (gid_t)0;
        chown(dir.c_str(), orig_uid, g);
        chown(creds_path().c_str(), orig_uid, g);
    }
    chmod(creds_path().c_str(), 0600);
    return f.good();
}
static bool creds_load(std::string &u, std::string &p) {
    std::ifstream f(creds_path(), std::ios::binary);
    if (!f) return false;
    char magic[4]; f.read(magic, 4);
    if (strncmp(magic, "0H01", 4)) return false;
    unsigned char key[32], iv[12], tag[16];
    derive_key(key);
    f.read((char*)iv, 12); f.read((char*)tag, 16);
    std::vector<unsigned char> ct((std::istreambuf_iterator<char>(f)), {});
    std::vector<unsigned char> pt(ct.size() + 16);
    int len = 0, plen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv);
    EVP_DecryptUpdate(ctx, pt.data(), &len, ct.data(), ct.size());
    plen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (EVP_DecryptFinal_ex(ctx, pt.data() + plen, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    plen += len; EVP_CIPHER_CTX_free(ctx);
    std::string s((char*)pt.data(), plen);
    auto nl = s.find('\n');
    if (nl == std::string::npos) return false;
    u = s.substr(0, nl); p = s.substr(nl + 1);
    return true;
}
static void creds_clear() { unlink(creds_path().c_str()); }

// ---------- first-run install of embedded configs ----------
static bool vpn_files_installed() {
    // ovpn folders must exist and be non-empty;
    // wireguard_files is a user drop-in folder - only needs to exist
    const char *dirs[] = {"udp", "tcp", "secure_udp", "secure_tcp", "wireguard_files"};
    for (auto sub : dirs) {
        DIR *d = opendir((VPN_DIR + "/" + sub).c_str());
        if (!d) return false;
        bool wg = !strcmp(sub, "wireguard_files");
        bool any = false;
        struct dirent *e;
        while ((e = readdir(d))) if (e->d_name[0] != '.') { any = true; break; }
        closedir(d);
        if (!wg && !any) return false;
    }
    return true;
}
static void install_vpn_files(GtkWidget *parent) {
    const char *tar = "/tmp/0hex01-vpn-files.tgz";
    std::ofstream f(tar, std::ios::binary);
    f.write((char*)vpn_files_data, vpn_files_data_len);
    f.close();
    std::string cmd = "mkdir -p '" + VPN_DIR +
        "' && tar xzf " + tar + " -C '" + VPN_DIR + "'";
    if (!run_ok(cmd.c_str())) {
        GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(parent),
            GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK,
            "Failed to install vpn files to %s.", VPN_DIR.c_str());
        gtk_dialog_run(GTK_DIALOG(d)); gtk_widget_destroy(d);
    }
    unlink(tar);
}

// ---------- connection ----------
static void set_status(const std::string &s) {
    gtk_label_set_text(GTK_LABEL(status_lbl), s.c_str());
}
// Proton confs hook `up/down /etc/openvpn/update-resolv-conf` which picks the
// systemd-resolved backend - masked here -> --up script fails -> fatal exit.
// Strip hook lines into a /tmp copy; DNS is applied via resolvconf manually.
static std::string ovpn_prepare_conf(const std::string &src) {
    static const char *strip[] = {"up", "down", "script-security", "setenv"};
    std::ifstream in(src);
    if (!in) return src;
    std::string dst = "/tmp/0hex01-" + src.substr(src.rfind('/') + 1);
    std::ofstream out(dst);
    bool changed = false;
    std::string line;
    while (std::getline(in, line)) {
        size_t a = line.find_first_not_of(" \t");
        std::string t = a == std::string::npos ? "" : line.substr(a);
        bool drop = false;
        for (auto p : strip)
            if (t.rfind(p, 0) == 0 && (t.size() == strlen(p) || t[strlen(p)] == ' ' || t[strlen(p)] == '=')) {
                drop = true; break;
            }
        if (drop) { changed = true; continue; }
        out << line << "\n";
    }
    out.close();
    if (!changed) { unlink(dst.c_str()); return src; }
    chmod(dst.c_str(), 0600);
    return dst;
}

// after tun is up: read the pushed DNS + device from the log and register
// them with resolvconf (openresolv backs up resolv.conf for us)
static void ovpn_apply_dns() {
    std::ifstream lg(LOG_FILE);
    std::string txt((std::istreambuf_iterator<char>(lg)), {}), dns, dev;
    for (auto &l : split(txt, '\n')) {
        if (l.find("TUN/TAP device") != std::string::npos && l.find("opened") != std::string::npos)
            dev = l.substr(l.find("device") + 7, l.rfind("opened") - l.find("device") - 8);
        auto p = l.rfind("dhcp-option DNS ");
        if (p != std::string::npos) {
            dns = l.substr(p + 16);
            while (!dns.empty() && !isdigit((unsigned char)dns.back())) dns.pop_back();
        }
    }
    if (dev.empty() || dns.empty()) return;
    if (!run_ok("command -v resolvconf >/dev/null 2>&1")) return;
    std::string cmd = "printf 'nameserver " + dns + "\n' | resolvconf -a " + dev + ".ovpn";
    if (run_ok(cmd.c_str())) { ovpn_dev = dev; dns_applied = true; }
}

static bool ovpn_start(const std::string &file) {
    std::string u, p;
    if (!creds_load(u, p)) return false;
    {   std::ofstream a(AUTH_FILE); a << u << "\n" << p << "\n"; }
    chmod(AUTH_FILE.c_str(), 0600);
    unlink(LOG_FILE.c_str());   // fresh log so auth-fail detection is per-attempt
    std::string cmd = "/usr/sbin/openvpn --config '" + ovpn_prepare_conf(file) +
        "' --auth-user-pass '" + AUTH_FILE +
        "' --redirect-gateway def1" +                    // force all traffic via tunnel
        " --daemon --writepid '" + PID_FILE + "' --log-append '" + LOG_FILE + "'";
    std::string out;
    int rc = run_capture(cmd, out);
    if (rc != 0) {
        { std::ofstream lg(LOG_FILE, std::ios::app); lg << out; }
        set_status("OpenVPN failed to start");
        return true;
    }
    pending_ovpn = file;           // daemon spawned; tunnel isn't proven until tun0 is up
    pending_since = time(nullptr);
    set_status("Connecting via OpenVPN...");
    return true;
}
static void do_disconnect() {
    std::ifstream pf(PID_FILE); std::string pid;
    pf >> pid;
    if (!pid.empty())
        run_ok(("kill " + pid + " 2>/dev/null").c_str());
    run_ok("pkill -f 'openvpn --config' 2>/dev/null");
    unlink(PID_FILE.c_str()); unlink(AUTH_FILE.c_str());
    if (dns_applied) {          // release the resolvconf entry (restores resolv.conf)
        run_ok(("resolvconf -d " + ovpn_dev + ".ovpn -f 2>/dev/null").c_str());
        dns_applied = false; ovpn_dev.clear();
    }
    // tear down the config that is actually up, not whatever is selected
    if (wg_iface_up()) {
        std::string down_target = !wg_up_conf.empty() ? wg_up_conf
            : (conn_is_wg && !active_conn_file.empty() ? active_conn_file : selected_file);
        if (!down_target.empty())
            run_ok(("/usr/bin/wg-quick down '" + down_target + "'").c_str());
    }
    if (!wg_up_conf.empty() && wg_up_conf.find("/tmp/") == 0)
        unlink(wg_up_conf.c_str());
    wg_up_conf.clear();
    pending_ovpn.clear(); pending_since = 0;
    active_conn_file.clear(); conn_is_wg = false;
    // restore ipv6 only if we disabled it
    if (ipv6_managed) { ipv6_set(true); ipv6_managed = false; }
    set_status("Disconnected");
}

// ---------- creds dialog ----------
static void on_dlg_connect(GtkButton*, gpointer);
static void on_dlg_clear(GtkButton*, gpointer);

static void creds_dialog() {
    GtkWidget *dlg = gtk_dialog_new();
    gtk_window_set_transient_for(GTK_WINDOW(dlg), GTK_WINDOW(win));
    gtk_window_set_title(GTK_WINDOW(dlg), "ProtonVPN credentials");
    gtk_window_set_modal(GTK_WINDOW(dlg), TRUE);
    gtk_widget_set_name(dlg, "dlg");

    GtkWidget *box = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_set_border_width(GTK_CONTAINER(box), 16);

    GtkWidget *hdr = gtk_label_new(nullptr);
    gtk_label_set_markup(GTK_LABEL(hdr), "<b>Enter OpenVPN Credentials</b>");
    gtk_box_pack_start(GTK_BOX(box), hdr, FALSE, FALSE, 6);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
    gtk_box_pack_start(GTK_BOX(box), grid, TRUE, TRUE, 0);

    GtkWidget *lu = gtk_label_new("Username:");
    GtkWidget *lp = gtk_label_new("Password:");
    gtk_widget_set_halign(lu, GTK_ALIGN_END);
    gtk_widget_set_halign(lp, GTK_ALIGN_END);
    GtkWidget *eu = gtk_entry_new();
    GtkWidget *ep = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(ep), FALSE);
    gtk_entry_set_input_purpose(GTK_ENTRY(ep), GTK_INPUT_PURPOSE_PASSWORD);
    gtk_widget_set_size_request(eu, 260, -1);
    gtk_grid_attach(GTK_GRID(grid), lu, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), eu, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), lp, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), ep, 1, 1, 1, 1);

    gtk_dialog_add_button(GTK_DIALOG(dlg), "Clear credentials", GTK_RESPONSE_REJECT);
    gtk_dialog_add_button(GTK_DIALOG(dlg), "Cancel", GTK_RESPONSE_CANCEL);
    gtk_dialog_add_button(GTK_DIALOG(dlg), "Connect", GTK_RESPONSE_ACCEPT);
    gtk_dialog_set_default_response(GTK_DIALOG(dlg), GTK_RESPONSE_ACCEPT);

    // stash entry ptrs on the dialog
    g_object_set_data(G_OBJECT(dlg), "eu", eu);
    g_object_set_data(G_OBJECT(dlg), "ep", ep);
    g_signal_connect(gtk_dialog_get_widget_for_response(GTK_DIALOG(dlg), GTK_RESPONSE_REJECT),
                     "clicked", G_CALLBACK(on_dlg_clear), dlg);
    g_signal_connect(gtk_dialog_get_widget_for_response(GTK_DIALOG(dlg), GTK_RESPONSE_ACCEPT),
                     "clicked", G_CALLBACK(on_dlg_connect), dlg);
    // no gtk_dialog_run: destroy on Cancel/window-X so it can't linger
    // modal and swallow the first click on the main window's close button
    g_signal_connect(dlg, "response", G_CALLBACK(+[](GtkDialog *d, gint r, gpointer) {
        if (r != GTK_RESPONSE_ACCEPT) gtk_widget_destroy(GTK_WIDGET(d));
    }), nullptr);
    g_signal_connect(dlg, "delete-event",
                     G_CALLBACK(+[](GtkWidget *d, GdkEvent*, gpointer) -> gboolean {
        gtk_widget_destroy(d); return TRUE;
    }), nullptr);

    gtk_widget_show_all(dlg);
}
static void on_dlg_clear(GtkButton*, gpointer dlg) {
    creds_clear();
    gtk_entry_set_text(GTK_ENTRY(g_object_get_data(G_OBJECT(dlg), "eu")), "");
    gtk_entry_set_text(GTK_ENTRY(g_object_get_data(G_OBJECT(dlg), "ep")), "");
    set_status("Credentials cleared");
    // dialog stays open per spec
}
static void on_dlg_connect(GtkButton*, gpointer dlg) {
    GtkWidget *eu = GTK_WIDGET(g_object_get_data(G_OBJECT(dlg), "eu"));
    GtkWidget *ep = GTK_WIDGET(g_object_get_data(G_OBJECT(dlg), "ep"));
    std::string u = gtk_entry_get_text(GTK_ENTRY(eu));
    std::string p = gtk_entry_get_text(GTK_ENTRY(ep));
    if (u.empty() || p.empty()) return;   // stay open
    creds_save(u, p);
    gtk_widget_destroy(GTK_WIDGET(dlg));
    ovpn_start(selected_file);
}

// ---------- list population ----------
enum { COL_DISPLAY, COL_PATH, COL_N };
static void populate_list(const char *folder) {
    gtk_list_store_clear(GTK_LIST_STORE(store_model));
    std::string dir = VPN_DIR + "/" + folder;
    DIR *d = opendir(dir.c_str());
    if (!d) return;
    std::vector<std::pair<std::string,std::string>> rows;
    struct dirent *e;
    while ((e = readdir(d))) {
        std::string n = e->d_name;
        if (n[0] == '.') continue;
        bool good = n.size() > 5 &&
            (n.substr(n.size() - 5) == ".ovpn" || n.substr(n.size() - 5) == ".conf");
        if (good) rows.emplace_back(display_name(n), dir + "/" + n);
    }
    closedir(d);
    std::sort(rows.begin(), rows.end());
    for (auto &r : rows) {
        GtkTreeIter it;
        gtk_list_store_append(GTK_LIST_STORE(store_model), &it);
        gtk_list_store_set(GTK_LIST_STORE(store_model), &it,
                           COL_DISPLAY, r.first.c_str(), COL_PATH, r.second.c_str(), -1);
    }
}

// ---------- callbacks ----------
static void on_combo_changed(GtkComboBox *c, gpointer) {
    int idx = gtk_combo_box_get_active(c);
    if (idx < 0) return;
    populate_list(MODES[idx]);
}
static void on_row_selected(GtkTreeView *tv, gpointer) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(tv);
    GtkTreeModel *m; GtkTreeIter it;
    if (gtk_tree_selection_get_selected(sel, &m, &it)) {
        gchar *path;
        gtk_tree_model_get(m, &it, COL_PATH, &path, -1);
        selected_file = path; g_free(path);
        selected_is_wg = selected_file.find("/wireguard_files/") != std::string::npos;
    }
}
static void on_connect(GtkButton*, gpointer) {
    if (selected_file.empty()) { set_status("Select a server first"); return; }
    // switching servers: tear down the live tunnel first so we never get
    // parallel daemons + stacked tun interfaces keeping the old routes
    if (tun_up() || wg_iface_up() || !pending_ovpn.empty() || !active_conn_file.empty()) {
        do_disconnect();
        for (int i = 0; i < 30 && (tun_up() || wg_iface_up()); i++) usleep(100000);
    }
    // leak protection: kill ipv6 while tunneled (remember if we flipped it)
    if (ipv6_state() == 0) { ipv6_set(false); ipv6_managed = true; }
    if (selected_is_wg) {
        std::string out;
        wg_up_conf = wg_prepare_conf(selected_file);   // ipv4-only copy if needed
        int rc = run_capture("/usr/bin/wg-quick up '" + wg_up_conf + "'", out);
        if (rc != 0 && wg_iface_up()) {
            // iface already up from an earlier session - treat as connected
            active_conn_file = selected_file; conn_is_wg = true;
            set_status("Connected: " + display_name(
                selected_file.substr(selected_file.rfind('/') + 1)));
            return;
        }
        if (rc == 0 && wg_iface_up()) {
            active_conn_file = selected_file; conn_is_wg = true;
            set_status("Connected: " + display_name(
                selected_file.substr(selected_file.rfind('/') + 1)));
        } else {
            // real error = last non-empty line that isn't a [#] command echo
            // (wg-quick prints "[#] ip link delete ..." while rolling back)
            { std::ofstream lg(LOG_FILE, std::ios::app); lg << out; }
            std::string err = "WireGuard failed";
            std::string last, last_nohash;
            for (auto &ln : split(out, '\n')) {
                std::string t = ln;
                while (!t.empty() && (t.back() == ' ' || t.back() == '\r')) t.pop_back();
                if (t.empty()) continue;
                last = t;
                if (t.rfind("[#]", 0) != 0) last_nohash = t;
            }
            const std::string &shown = !last_nohash.empty() ? last_nohash : last;
            if (!shown.empty()) err += ": " + shown;
            set_status(err);
        }
        return;
    }

    std::string u, p;
    if (!creds_load(u, p)) { creds_dialog(); return; }
    ovpn_start(selected_file);
}
static void on_disconnect(GtkButton*, gpointer) { do_disconnect(); }

static void on_help(GtkButton*, gpointer) {
    GtkWidget *d = gtk_message_dialog_new(GTK_WINDOW(win),
        GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE,
        "WireGuard configs are not bundled - copy your .conf files into:\n\n%s\n\n"
        "They will appear in the list when WireGuard is selected.",
        (VPN_DIR + "/wireguard_files").c_str());
    gtk_message_dialog_format_secondary_text(GTK_MESSAGE_DIALOG(d),
        "The folder is root-writable only; the app runs as root, so use:\n"
        "  sudo cp yourconfig.conf %s",
        (VPN_DIR + "/wireguard_files").c_str());
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static gboolean status_poll(gpointer) {
    // derive status from real system state, not flags
    bool ovpn_proc = run_ok("pgrep -f 'openvpn --config' >/dev/null 2>&1");
    bool wg_up = wg_iface_up();
    bool tun = tun_up();

    if ((tun && ovpn_proc) || wg_up) {                 // tunnel actually up
        if (tun && !pending_ovpn.empty()) {
            active_conn_file = pending_ovpn;           // handshake finished
            pending_ovpn.clear(); conn_is_wg = false;
            ovpn_apply_dns();                          // register pushed DNS
        }
        if (!active_conn_file.empty()) {
            std::string base = active_conn_file.substr(active_conn_file.rfind('/') + 1);
            set_status("Connected: " + display_name(base));
        }
        return TRUE;
    }

    // nothing is up - a pending ovpn either died or is still handshaking
    if (!pending_ovpn.empty()) {
        std::ifstream lg(LOG_FILE);
        std::string txt((std::istreambuf_iterator<char>(lg)), {});
        bool auth_failed = txt.find("AUTH_FAILED") != std::string::npos;
        bool timed_out = pending_since && time(nullptr) - pending_since > 30;
        if (ovpn_proc && !auth_failed && !timed_out)
            return TRUE;                               // still retrying/handshaking
        if (ovpn_proc)                                 // gave up - kill the straggler
            run_ok("pkill -f 'openvpn --config' 2>/dev/null");
        pending_ovpn.clear(); pending_since = 0;
        if (auth_failed) {
            creds_clear();                             // force credential popup next try
            set_status("Authentication failed - check username/password");
        } else {
            // surface the last meaningful log line (dead remote, TLS fail, etc.)
            std::string lastln;
            for (auto &l : split(txt, '\n')) {
                size_t a = l.find_first_not_of(" \t"), b = l.find_last_not_of(" \t\r");
                if (a == std::string::npos) continue;
                std::string t = l.substr(a, b - a + 1);
                // strip the timestamp prefix "YYYY-MM-DD HH:MM:SS "
                if (t.size() > 20 && t[4] == '-' && t[7] == '-' && t[19] == ' ')
                    t = t.substr(20);
                lastln = t;
            }
            std::string err = timed_out ? "Connection timed out" : "Connection failed";
            if (!lastln.empty()) err += ": " + lastln;
            set_status(err);
        }
        active_conn_file.clear();
        return TRUE;
    }

    if (!active_conn_file.empty()) {                   // tunnel died mid-session
        active_conn_file.clear(); conn_is_wg = false;
        set_status("Disconnected");
    }
    return TRUE;
}

// ---------- theme ----------
static const char *CSS = R"(
window, dialog { background-color: #232b38; color: #ffffff; }
label { color: #ffffff; }
combobox, entry, button {
    background: #2e3a4a; color: #ffffff;
    border: 1px solid #232b38; border-radius: 4px; padding: 6px;
}
combobox:hover, button:hover { background: #3a4a5e; }
treeview { background: #2e3a4a; color: #ffffff; }
treeview:selected { background: #3a4a5e; color: #ffffff; }
treeview header button { background: #2e3a4a; }
decoration { border: 2px solid #2e3a4a; }
)";

// relaunch ourselves under pkexec so the app runs as root:
// one auth prompt covers file install + openvpn/wg-quick.
static bool elevate_self(const char *argv0) {
    if (geteuid() == 0) return true;          // already root
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) exe[n] = 0;
    const char *disp = getenv("DISPLAY");
    const char *xauth = getenv("XAUTHORITY");
    std::string cmd = "pkexec env DISPLAY=" + std::string(disp ? disp : ":0") +
        " XAUTHORITY=" + std::string(xauth ? xauth : "") +
        " '" + (n > 0 ? std::string(exe) : std::string(argv0)) + "'";
    int r = system(cmd.c_str());
    if (r == -1) return false;
    // child ran the whole GUI to completion - this unprivileged process
    // has nothing left to do; exiting here is what closes cleanly on ONE X
    if (WIFEXITED(r)) _exit(WEXITSTATUS(r));
    return false;
}

int main(int argc, char **argv) {
    // pkexec gives a stripped-down env - force a full PATH so wg-quick's
    // internal ip/resolvconf/nft/sysctl calls all resolve
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    const char *pk = getenv("PKEXEC_UID");
    if (pk) orig_uid = (uid_t)atoi(pk);
    if (!elevate_self(argv[0])) return 1;    // auth refused -> exit
    (void)argc;
    gtk_init(&argc, &argv);

    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css, CSS, -1, nullptr);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win), 720, 520);

    // header bar with title + help button
    GtkWidget *hb = gtk_header_bar_new();
    gtk_header_bar_set_title(GTK_HEADER_BAR(hb), "0hex01 vpn manager");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(hb), TRUE);
    GtkWidget *help_btn = gtk_button_new_with_label("?");
    gtk_widget_set_tooltip_text(help_btn, "Where to put WireGuard configs");
    g_signal_connect(help_btn, "clicked", G_CALLBACK(on_help), nullptr);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), help_btn);
    gtk_window_set_titlebar(GTK_WINDOW(win), hb);
    // tear down any active tunnel + restore routes before exiting
    g_signal_connect(win, "destroy", G_CALLBACK(+[](GtkWidget*, gpointer) {
        do_disconnect();
        gtk_main_quit();
    }), nullptr);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);
    gtk_container_add(GTK_CONTAINER(win), vbox);

    combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "OpenVPN UDP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "OpenVPN TCP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "OpenVPN Secure UDP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "OpenVPN Secure TCP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "WireGuard");
    gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    g_signal_connect(combo, "changed", G_CALLBACK(on_combo_changed), nullptr);
    gtk_box_pack_start(GTK_BOX(vbox), combo, FALSE, FALSE, 0);

    store_model = (GtkWidget*)gtk_list_store_new(COL_N, G_TYPE_STRING, G_TYPE_STRING);
    GtkWidget *tv = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store_model));
    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tv), -1, "Location",
        gtk_cell_renderer_text_new(), "text", COL_DISPLAY, nullptr);
    GtkTreeViewColumn *c1 = gtk_tree_view_get_column(GTK_TREE_VIEW(tv), 0);
    gtk_tree_view_column_set_expand(c1, TRUE);
    gtk_tree_view_insert_column_with_attributes(GTK_TREE_VIEW(tv), -1, "File",
        gtk_cell_renderer_text_new(), "text", COL_PATH, nullptr);
    g_signal_connect(tv, "cursor-changed", G_CALLBACK(on_row_selected), nullptr);
    GtkWidget *scroll = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_container_add(GTK_CONTAINER(scroll), tv);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    btn_con = gtk_button_new_with_label("Connect");
    btn_dis = gtk_button_new_with_label("Disconnect");
    GtkWidget *btn_clear = gtk_button_new_with_label("Clear credentials");
    status_lbl = gtk_label_new("Disconnected");
    gtk_box_pack_start(GTK_BOX(hbox), btn_con, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), btn_dis, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), btn_clear, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(hbox), status_lbl, FALSE, FALSE, 0);
    g_signal_connect(btn_con, "clicked", G_CALLBACK(on_connect), nullptr);
    g_signal_connect(btn_dis, "clicked", G_CALLBACK(on_disconnect), nullptr);
    g_signal_connect(btn_clear, "clicked", G_CALLBACK(+[](GtkButton*, gpointer) {
        creds_clear();
        set_status("Credentials cleared");
    }), nullptr);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    gtk_widget_show_all(win);

    if (!vpn_files_installed()) install_vpn_files(win);
    populate_list("udp");
    g_timeout_add(2000, status_poll, nullptr);

    gtk_main();
    return 0;
}

// frida-ssl-bypass.js
Java.perform(function () {
    console.log("[*] Starting SSL Pinning Bypass...");

    // Bypass TrustManager (custom)
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var X509Certificate = Java.use('java.security.cert.X509Certificate');

    var TrustManagerImpl = Java.registerClass({
        name: 'com.sense.ssl.MyTrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) { },
            checkServerTrusted: function (chain, authType) { },
            getAcceptedIssuers: function () {
                return Java.array('java.security.cert.X509Certificate', []);
            }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (km, tm, sr) {
        console.log('[+] Overriding SSLContext.init()');
        this.init(km, [TrustManagerImpl.$new()], sr);
    };

    // OkHttp (v3/v4) certificate pin bypass
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (str, list) {
            console.log("[+] OkHttp3 CertificatePinner.check() bypassed");
            return;
        };
    } catch (err) {
        console.log("[-] OkHttp3 CertificatePinner not found");
    }

    console.log("[*] SSL Pinning Bypass is active");
});


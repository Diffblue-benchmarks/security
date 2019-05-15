package com.amazon.opendistroforelasticsearch.security.compliance;

import com.diffblue.deeptestutils.Reflector;
import com.diffblue.deeptestutils.mock.DTUMemberMatcher;
import com.google.common.cache.LoadingCache;
import org.joda.time.ReadableInstant;
import org.junit.runner.RunWith;
import org.joda.time.format.DateTimeFormatter;
import org.junit.Assert;
import org.junit.Test;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;

import static org.mockito.AdditionalMatchers.or;
import static org.mockito.Matchers.isA;
import static org.mockito.Matchers.isNull;

@RunWith(PowerMockRunner.class)
@PowerMockIgnore({"javax.management.*"})
public class ComplianceConfigTest {

    @Test
    public void testWriteHistoryEnabledForIndex() throws Exception {
        ComplianceConfig objectUnderTest = (ComplianceConfig) Reflector.getInstance(
                "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig");

        DateTimeFormatter dateTimeFormatter = PowerMockito.mock(DateTimeFormatter.class);
        Method printMethod = DTUMemberMatcher.method(DateTimeFormatter.class, "print", ReadableInstant.class);
        PowerMockito.doReturn("3")
                .when(dateTimeFormatter, printMethod)
                .withArguments(or(isA(ReadableInstant.class), isNull(ReadableInstant.class)));
        Reflector.setField(objectUnderTest, "opendistrosecurityIndex", "a\'b\'c");
        Reflector.setField(objectUnderTest, "auditLogPattern", dateTimeFormatter);

        Assert.assertFalse(objectUnderTest.writeHistoryEnabledForIndex("3"));


        Reflector.setField(objectUnderTest, "watchedWriteIndices", new ArrayList<String>());
        Reflector.setField(objectUnderTest, "auditLogIndex", "3");

        Assert.assertFalse(objectUnderTest.writeHistoryEnabledForIndex("1234"));
        Assert.assertFalse(objectUnderTest.writeHistoryEnabledForIndex(null));
        Assert.assertFalse(objectUnderTest.writeHistoryEnabledForIndex("3"));
        Assert.assertFalse(objectUnderTest.writeHistoryEnabledForIndex("a\'b\'c"));
    }

    @Test
    public void testReadHistoryEnabledForIndex() throws Exception {
        ComplianceConfig objectUnderTest = (ComplianceConfig) Reflector.getInstance(
                "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig");

        Assert.assertFalse(objectUnderTest.readHistoryEnabledForIndex("a\'b\'c"));

        LoadingCache<String, Set> loadingCache = PowerMockito.mock(LoadingCache.class);
        Method getMethod = DTUMemberMatcher.method(LoadingCache.class, "get", Object.class);
        PowerMockito.doReturn(new HashSet())
                .when(loadingCache, getMethod)
                .withArguments(or(isA(Object.class), isNull(Object.class)));
        Reflector.setField(objectUnderTest, "cache", loadingCache);
        Reflector.setField(objectUnderTest, "enabled", true);
        Reflector.setField(objectUnderTest, "opendistrosecurityIndex", "a\'b\'c");

        Assert.assertFalse(objectUnderTest.readHistoryEnabledForIndex("a\'b\'c"));
        Assert.assertFalse(objectUnderTest.readHistoryEnabledForIndex("Bar"));
    }

    @Test
    public void testReadHistoryEnabledForField1() throws Exception {
        ComplianceConfig objectUnderTest = (ComplianceConfig) Reflector.getInstance(
                "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig");

        Assert.assertFalse(objectUnderTest.readHistoryEnabledForField("a/b/c", "a\'b\'c"));

        LoadingCache<String, Set> loadingCache = PowerMockito.mock(LoadingCache.class);
        Method getMethod = DTUMemberMatcher.method(LoadingCache.class, "get", Object.class);
        PowerMockito.doReturn(new HashSet())
                .when(loadingCache, getMethod)
                .withArguments(or(isA(Object.class), isNull(Object.class)));
        Reflector.setField(objectUnderTest, "cache", loadingCache);
        Reflector.setField(objectUnderTest, "logInternalConfig", true);
        Reflector.setField(objectUnderTest, "enabled", true);
        Reflector.setField(objectUnderTest, "opendistrosecurityIndex", "a/b/c");

        Assert.assertTrue(objectUnderTest.readHistoryEnabledForField("a/b/c", "a\'b\'c"));
        Assert.assertFalse(objectUnderTest.readHistoryEnabledForField("1234", "a\'b\'c"));
    }


    @Test
    public void testReadHistoryEnabledForField2() throws Exception {
        ComplianceConfig objectUnderTest = (ComplianceConfig) Reflector.getInstance(
                "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig");

        LoadingCache<String, Set> loadingCache = PowerMockito.mock(LoadingCache.class);
        HashSet hashSet = new HashSet();
        hashSet.add("BAZ");
        Method getMethod = DTUMemberMatcher.method(LoadingCache.class, "get", Object.class);
        PowerMockito.doReturn(hashSet)
                .when(loadingCache, getMethod)
                .withArguments(or(isA(Object.class), isNull(Object.class)));
        Reflector.setField(objectUnderTest, "cache", loadingCache);
        Reflector.setField(objectUnderTest, "enabled", true);
        Reflector.setField(objectUnderTest, "opendistrosecurityIndex", "a/b/c");

        Assert.assertTrue(objectUnderTest.readHistoryEnabledForField("2", "BAZ"));
    }

    @Test
    public void testLogDiffsForWrite() throws InvocationTargetException {
        ComplianceConfig objectUnderTest = (ComplianceConfig) Reflector.getInstance(
                "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig");

        Reflector.setField(objectUnderTest, "logDiffsForWrite", false);
        Reflector.setField(objectUnderTest, "logWriteMetadataOnly", false);

        Assert.assertFalse(objectUnderTest.logDiffsForWrite());
    }


    @Test
    public void testLogReadMetadataOnly() throws InvocationTargetException {
        final ComplianceConfig objectUnderTest = (ComplianceConfig) Reflector.getInstance(
                "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig");
        Reflector.setField(objectUnderTest, "logReadMetadataOnly", false);

        Assert.assertFalse(objectUnderTest.logReadMetadataOnly());
    }

    @Test
    public void testIsIndexImmutable() throws Exception {
        ComplianceConfig objectUnderTest = (ComplianceConfig) Reflector.getInstance(
                "com.amazon.opendistroforelasticsearch.security.compliance.ComplianceConfig");

        Assert.assertFalse(objectUnderTest.isIndexImmutable("foo"));

        Set<String> hashset = new HashSet<>();
        Reflector.setField(objectUnderTest, "immutableIndicesPatterns", hashset);
        Reflector.setField(objectUnderTest, "enabled", true);
        Reflector.setField(objectUnderTest, "opendistrosecurityIndex", "a/b/c");

        Assert.assertFalse(objectUnderTest.isIndexImmutable("foo"));
    }
}

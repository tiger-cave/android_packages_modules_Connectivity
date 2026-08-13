/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "NetworkStats"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include <jni.h>

#include <nativehelper/jni_macros.h>
#include <nativehelper/JNIHelp.h>
#include <nativehelper/ScopedUtfChars.h>
#include <nativehelper/ScopedLocalRef.h>
#include <nativehelper/ScopedPrimitiveArray.h>

#include <cutils/properties.h>
#include <utils/Log.h>
#include <utils/misc.h>

#include "android-base/unique_fd.h"
#include "bpf/BpfUtils.h"
#include "netdbpf/BpfNetworkStats.h"

using android::bpf::parseBpfNetworkStatsDetail;
using android::bpf::stats_line;

namespace android {

static constexpr const char* EBPF_SUPPORTED_PROPERTY = "ro.kernel.ebpf.supported";
static constexpr const char* QTAGUID_IFACE_STATS = "/proc/net/xt_qtaguid/iface_stat_fmt";
static constexpr const char* QTAGUID_UID_STATS = "/proc/net/xt_qtaguid/stats";

static jclass gStringClass;

static struct {
    jfieldID size;
    jfieldID capacity;
    jfieldID iface;
    jfieldID uid;
    jfieldID set;
    jfieldID tag;
    jfieldID metered;
    jfieldID roaming;
    jfieldID defaultNetwork;
    jfieldID rxBytes;
    jfieldID rxPackets;
    jfieldID txBytes;
    jfieldID txPackets;
    jfieldID operations;
} gNetworkStatsClassInfo;

static jobjectArray get_string_array(JNIEnv* env, jobject obj, jfieldID field, int size, bool grow)
{
    if (!grow) {
        jobjectArray array = (jobjectArray)env->GetObjectField(obj, field);
        if (array) return array;
    }
    return env->NewObjectArray(size, gStringClass, NULL);
}

static jintArray get_int_array(JNIEnv* env, jobject obj, jfieldID field, int size, bool grow)
{
    if (!grow) {
        jintArray array = (jintArray)env->GetObjectField(obj, field);
        if (array) return array;
    }
    return env->NewIntArray(size);
}

static jlongArray get_long_array(JNIEnv* env, jobject obj, jfieldID field, int size, bool grow)
{
    if (!grow) {
        jlongArray array = (jlongArray)env->GetObjectField(obj, field);
        if (array) return array;
    }
    return env->NewLongArray(size);
}

static bool useBpfStats() {
    char value[PROP_VALUE_MAX] = "";
    return __system_property_get(EBPF_SUPPORTED_PROPERTY, value) == 0 ||
            strcmp(value, "false") != 0;
}

static int legacyReadNetworkStatsDetail(std::vector<stats_line>* lines) {
    FILE* fp = fopen(QTAGUID_UID_STATS, "re");
    if (fp == nullptr) return -errno;

    char buffer[512];
    int lastIdx = 1;
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        stats_line line = {};
        int idx;
        uint64_t rawTag;
        uint64_t rxBytes;
        uint64_t rxPackets;
        uint64_t txBytes;
        uint64_t txPackets;
        const int matched = sscanf(buffer,
                "%d %31s 0x%" SCNx64 " %u %u %" SCNu64 " %" SCNu64
                " %" SCNu64 " %" SCNu64,
                &idx, line.iface, &rawTag, &line.uid, &line.set,
                &rxBytes, &rxPackets, &txBytes, &txPackets);
        if (matched != 9) continue;  // Includes the header line.
        if (idx != lastIdx + 1) {
            ALOGE("Inconsistent qtaguid index %d after %d", idx, lastIdx);
            fclose(fp);
            return -EINVAL;
        }
        lastIdx = idx;
        line.tag = rawTag >> 32;
        line.rxBytes = rxBytes;
        line.rxPackets = rxPackets;
        line.txBytes = txBytes;
        line.txPackets = txPackets;
        lines->push_back(line);
    }

    if (ferror(fp)) {
        const int error = errno;
        fclose(fp);
        return error == 0 ? -EIO : -error;
    }
    return fclose(fp) == 0 ? 0 : -errno;
}

static int legacyReadNetworkStatsDev(std::vector<stats_line>* lines) {
    FILE* fp = fopen(QTAGUID_IFACE_STATS, "re");
    if (fp == nullptr) return -errno;

    char buffer[512];
    while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
        stats_line line = {};
        line.uid = static_cast<uint32_t>(-1);
        line.set = static_cast<uint32_t>(-1);
        uint64_t rxBytes;
        uint64_t rxPackets;
        uint64_t txBytes;
        uint64_t txPackets;
        const int matched = sscanf(buffer,
                "%31s %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                line.iface, &rxBytes, &rxPackets, &txBytes, &txPackets);
        if (matched == 5) {
            line.rxBytes = rxBytes;
            line.rxPackets = rxPackets;
            line.txBytes = txBytes;
            line.txPackets = txPackets;
            lines->push_back(line);
        }
    }

    if (ferror(fp)) {
        const int error = errno;
        fclose(fp);
        return error == 0 ? -EIO : -error;
    }
    return fclose(fp) == 0 ? 0 : -errno;
}

static int statsLinesToNetworkStats(JNIEnv* env, jclass clazz, jobject stats,
                            std::vector<stats_line>& lines) {
    int size = lines.size();

    bool grow = size > env->GetIntField(stats, gNetworkStatsClassInfo.capacity);

    ScopedLocalRef<jobjectArray> iface(env, get_string_array(env, stats,
            gNetworkStatsClassInfo.iface, size, grow));
    if (!iface.get()) return -1;

    ScopedIntArrayRW uid(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.uid, size, grow));
    if (!uid.get()) return -1;

    ScopedIntArrayRW set(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.set, size, grow));
    if (!set.get()) return -1;

    ScopedIntArrayRW tag(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.tag, size, grow));
    if (!tag.get()) return -1;

    ScopedIntArrayRW metered(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.metered, size, grow));
    if (!metered.get()) return -1;

    ScopedIntArrayRW roaming(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.roaming, size, grow));
    if (!roaming.get()) return -1;

    ScopedIntArrayRW defaultNetwork(env, get_int_array(env, stats,
            gNetworkStatsClassInfo.defaultNetwork, size, grow));
    if (!defaultNetwork.get()) return -1;

    ScopedLongArrayRW rxBytes(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.rxBytes, size, grow));
    if (!rxBytes.get()) return -1;

    ScopedLongArrayRW rxPackets(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.rxPackets, size, grow));
    if (!rxPackets.get()) return -1;

    ScopedLongArrayRW txBytes(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.txBytes, size, grow));
    if (!txBytes.get()) return -1;

    ScopedLongArrayRW txPackets(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.txPackets, size, grow));
    if (!txPackets.get()) return -1;

    ScopedLongArrayRW operations(env, get_long_array(env, stats,
            gNetworkStatsClassInfo.operations, size, grow));
    if (!operations.get()) return -1;

    for (int i = 0; i < size; i++) {
        ScopedLocalRef<jstring> ifaceString(env, env->NewStringUTF(lines[i].iface));
        env->SetObjectArrayElement(iface.get(), i, ifaceString.get());

        uid[i] = lines[i].uid;
        set[i] = lines[i].set;
        tag[i] = lines[i].tag;
        // Metered, roaming and defaultNetwork are populated in Java-land.
        rxBytes[i] = lines[i].rxBytes;
        rxPackets[i] = lines[i].rxPackets;
        txBytes[i] = lines[i].txBytes;
        txPackets[i] = lines[i].txPackets;
    }

    env->SetIntField(stats, gNetworkStatsClassInfo.size, size);
    if (grow) {
        env->SetIntField(stats, gNetworkStatsClassInfo.capacity, size);
        env->SetObjectField(stats, gNetworkStatsClassInfo.iface, iface.get());
        env->SetObjectField(stats, gNetworkStatsClassInfo.uid, uid.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.set, set.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.tag, tag.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.metered, metered.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.roaming, roaming.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.defaultNetwork,
                defaultNetwork.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.rxBytes, rxBytes.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.rxPackets, rxPackets.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.txBytes, txBytes.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.txPackets, txPackets.getJavaArray());
        env->SetObjectField(stats, gNetworkStatsClassInfo.operations, operations.getJavaArray());
    }
    return 0;
}

static int readNetworkStatsDetail(JNIEnv* env, jclass clazz, jobject stats) {
    std::vector<stats_line> lines;

    const int ret = useBpfStats() ? parseBpfNetworkStatsDetail(&lines)
                                  : legacyReadNetworkStatsDetail(&lines);
    if (ret < 0) {
        ALOGE("No usable UID network stats backend: %s", strerror(-ret));
        lines.clear();
    }

    return statsLinesToNetworkStats(env, clazz, stats, lines);
}

static int readNetworkStatsDev(JNIEnv* env, jclass clazz, jobject stats) {
    std::vector<stats_line> lines;

    const int ret = useBpfStats() ? parseBpfNetworkStatsDev(&lines)
                                  : legacyReadNetworkStatsDev(&lines);
    if (ret < 0) {
        ALOGE("No usable interface network stats backend: %s", strerror(-ret));
        lines.clear();
    }

    return statsLinesToNetworkStats(env, clazz, stats, lines);
}

static const JNINativeMethod gMethods[] = {
    MAKE_JNI_NATIVE_METHOD("nativeReadNetworkStatsDetail", "(Landroid/net/NetworkStats;)I", readNetworkStatsDetail),
    MAKE_JNI_NATIVE_METHOD("nativeReadNetworkStatsDev", "(Landroid/net/NetworkStats;)I", readNetworkStatsDev),
};

int register_android_server_net_NetworkStatsFactory(JNIEnv* env) {
    if (jniRegisterNativeMethods(env,
        "android/net/connectivity/com/android/server/net/NetworkStatsFactory",
        gMethods,
        NELEM(gMethods))) abort();

    gStringClass = env->FindClass("java/lang/String");
    if (!gStringClass) abort();
    gStringClass = static_cast<jclass>(env->NewGlobalRef(gStringClass));
    if (!gStringClass) abort();

    jclass clazz = env->FindClass("android/net/NetworkStats");
    gNetworkStatsClassInfo.size = env->GetFieldID(clazz, "size", "I");
    gNetworkStatsClassInfo.capacity = env->GetFieldID(clazz, "capacity", "I");
    gNetworkStatsClassInfo.iface = env->GetFieldID(clazz, "iface", "[Ljava/lang/String;");
    gNetworkStatsClassInfo.uid = env->GetFieldID(clazz, "uid", "[I");
    gNetworkStatsClassInfo.set = env->GetFieldID(clazz, "set", "[I");
    gNetworkStatsClassInfo.tag = env->GetFieldID(clazz, "tag", "[I");
    gNetworkStatsClassInfo.metered = env->GetFieldID(clazz, "metered", "[I");
    gNetworkStatsClassInfo.roaming = env->GetFieldID(clazz, "roaming", "[I");
    gNetworkStatsClassInfo.defaultNetwork = env->GetFieldID(clazz, "defaultNetwork", "[I");
    gNetworkStatsClassInfo.rxBytes = env->GetFieldID(clazz, "rxBytes", "[J");
    gNetworkStatsClassInfo.rxPackets = env->GetFieldID(clazz, "rxPackets", "[J");
    gNetworkStatsClassInfo.txBytes = env->GetFieldID(clazz, "txBytes", "[J");
    gNetworkStatsClassInfo.txPackets = env->GetFieldID(clazz, "txPackets", "[J");
    gNetworkStatsClassInfo.operations = env->GetFieldID(clazz, "operations", "[J");

    return 0;
}

}

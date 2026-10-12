#ifndef MECHANIZE_MIGRATION_METADATA_H
#define MECHANIZE_MIGRATION_METADATA_H
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdatomic.h>

typedef struct MechanizeMigrationMetadata {
    CFDataRef identity;
    SecAccessRef oldPolicy;
    atomic_bool attempted;
} MechanizeMigrationMetadata;

int mechanize_master_access_policy_matches(SecAccessRef, SecAccessRef);
int mechanize_master_prepare_single_acl(SecAccessRef, SecAccessRef, SecTrustedApplicationRef, SecAccessRef);
int mechanize_migration_metadata_verify(MechanizeMigrationMetadata *, const char *, const char *, const char *, const char *);
int mechanize_migration_metadata_inspect(const char *, const char *, const char *, const char *, const void *, int);
int mechanize_migration_executor_matches(const char *);
// 0=refused before dispatch, 1=metadata verified, -1=unknown/no replay.
int mechanize_migration_write(MechanizeMigrationMetadata *, const char *, const char *, const char *, const char *, const char *);
#endif

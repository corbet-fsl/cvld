/* Test-only GNU linker wrapper. No SQL, bindings, identifiers or timestamps.
 * Counters are libSQL's actual rows-read meter (1025), not fullscan estimates.
 * See libsql-ffi/bundled/src/sqlite3.h: LIBSQL_STMTSTATUS_ROWS_READ.
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
typedef struct sqlite3_stmt sqlite3_stmt;
extern int __real_sqlite3_step(sqlite3_stmt *);
extern int sqlite3_stmt_status(sqlite3_stmt *, int, int);
extern int sqlite3_stmt_isexplain(sqlite3_stmt *);
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int __wrap_sqlite3_step(sqlite3_stmt *stmt) {
    int before = sqlite3_stmt_status(stmt, 1025, 0);
    int result = __real_sqlite3_step(stmt);
    int after = sqlite3_stmt_status(stmt, 1025, 0);
    const char *path = getenv("CVLD_TOY_METER");
    if (path && !sqlite3_stmt_isexplain(stmt)) {
        int read = after >= before ? after - before : after;
        int returned = result == 100; /* SQLITE_ROW */
        if (read || returned) {
            char line[64];
            int size = snprintf(line, sizeof(line), "%d %d\n", read, returned);
            pthread_mutex_lock(&lock);
            int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (fd < 0 || write(fd, line, (size_t)size) != size) _exit(73);
            close(fd);
            pthread_mutex_unlock(&lock);
        }
    }
    return result;
}

/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * test_setup_logging() of src/shared/tests.c, for linking upstream's
 * test-udev-rule-runner from the reference build, which is configured
 * with -Dtests=false and so has no libsystemd-tests.
 *
 * 20261116 - Created by Claude (claude.ai, Anthropic) - scottfk
 */

#include <stdbool.h>

void log_set_assert_return_is_critical(bool b);
int log_set_max_level(int level);
void log_setup(void);

void test_setup_logging(int level);

void test_setup_logging(int level) {
        log_set_assert_return_is_critical(true);
        log_set_max_level(level);
        log_setup();
}

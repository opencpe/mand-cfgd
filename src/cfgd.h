/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __CFGD_H
#define __CFGD_H

#include <sys/queue.h>
#include <sys/tree.h>
#include <event.h>

void set_value(char *path, const char *str);

#endif

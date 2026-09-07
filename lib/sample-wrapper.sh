#!/bin/sh
# Automake test wrapper for lib/sample: sample takes a config file as its
# argument, and the harness runs tests with none. The config path is
# injected by AM_TESTS_ENVIRONMENT (abs_top_srcdir so VPATH builds work).
exec "$1" "$R2_SAMPLE_CONF"

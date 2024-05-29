#ifndef UTILS_H
#define UTILS_H

#ifdef DEBUG_TEST
#define DEBUG
#endif

#ifdef DEBUG_V
#define DEBUG
#endif

#define DEBUG //TODO remove
//TODO change includes !!
#ifdef DEBUG
#include <stdio.h>
#include <errno.h>
#include <string.h>

//info function
#define dprint_info(...) (pr_info(__VA_ARGS__))

// more verbose function
#ifdef DEBUG_TEST
#define dprint_info_test(...) (pr_info(__VA_ARGS__))
#endif

//verbose level
#ifdef DEBUG_V
#define dprint_info_v(...) (pr_info(__VA_ARGS__))
#endif

#else
#define dprint_info(...)
#define dprint_info_test(...)
#define dprint_info_v(...) 
#endif

#endif
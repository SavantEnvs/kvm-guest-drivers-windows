// What the WPP-generated *.tmh files provide: trace constants and a TraceEvents() that logs nothing.
#pragma once
#define TRACE_LEVEL_CRITICAL    1
#define TRACE_LEVEL_ERROR       2
#define TRACE_LEVEL_WARNING     3
#define TRACE_LEVEL_INFORMATION 4
#define TRACE_LEVEL_VERBOSE     5
#define DBG_INIT      0x1
#define DBG_PNP       0x2
#define DBG_POWER     0x4
#define DBG_WMI       0x8
#define DBG_CREATE_CLOSE 0x10
#define DBG_IOCTLS    0x20
#define DBG_WRITE     0x40
#define DBG_READ      0x80
#define DBG_DPC       0x100
#define DBG_INTERRUPT 0x200
#define DBG_LOCKS     0x400
#define DBG_QUEUEING  0x800
#define DBG_HW_ACCESS 0x1000
#define TraceEvents(...) ((void)0)

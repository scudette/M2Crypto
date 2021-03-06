/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* Copyright (c) 1999 Ng Pheng Siong. All rights reserved. */
/* $Id$ */

%{
#include <openssl/rc4.h>
%}

%apply Pointer NONNULL { RC4_KEY * };

%inline %{
RC4_KEY *rc4_new(void) {
    RC4_KEY *key;
    
    if (!(key = (RC4_KEY *)PyMem_Malloc(sizeof(RC4_KEY))))
        PyErr_SetString(PyExc_MemoryError, "rc4_new");
    return key;
}   

void rc4_free(RC4_KEY *key) {
    PyMem_Free((void *)key);
}

PyObject *rc4_set_key(RC4_KEY *key, PyObject *value) {
    Py_buffer vbuf;

    if (m2_PyObject_GetBufferInt(value, &vbuf, PyBUF_SIMPLE) == -1)
        return NULL;

    RC4_set_key(key, vbuf.len, vbuf.buf);
    m2_PyBuffer_Release(value, &vbuf);
    Py_INCREF(Py_None);
    return Py_None;
}

PyObject *rc4_update(RC4_KEY *key, PyObject *in) {
    PyObject *ret;
    void *out;
    Py_buffer buf;

    if (m2_PyObject_GetBuffer(in, &buf, PyBUF_SIMPLE) == -1)
        return NULL;

    if (!(out = PyMem_Malloc(buf.len))) {
        PyErr_SetString(PyExc_MemoryError, "expected a string object");
        m2_PyBuffer_Release(in, &buf);
        return NULL;
    }
    RC4(key, buf.len, buf.buf, out);
    ret = PyString_FromStringAndSize(out, buf.len);
    PyMem_Free(out);
    m2_PyBuffer_Release(in, &buf);
    return ret;
}

int rc4_type_check(RC4_KEY *key) {
    return 1;
}
%}

/* Copyright (c) 1999-2002 Ng Pheng Siong. All rights reserved.
 * Copyright (c) 2009-2010 Heikki Toivonen. All rights reserved.
*/
/* $Id$ */

%{
#include <openssl/x509v3.h>
%}

%inline %{
static PyObject *_util_err;

void util_init(PyObject *util_err) {
    Py_INCREF(util_err);
    _util_err = util_err;
}
    
PyObject *util_hex_to_string(PyObject *blob) {
    PyObject *obj;
    char *ret;
    Py_buffer buf;

    if (m2_PyObject_GetBuffer(blob, &buf, PyBUF_SIMPLE) == -1)
      return NULL;

    ret = hex_to_string((unsigned char *)buf.buf, buf.len);
    if (!ret) {
        PyErr_SetString(_util_err, ERR_reason_error_string(ERR_get_error()));
        m2_PyBuffer_Release(blob, &buf);
        return NULL;
    }
    obj = PyString_FromString(ret);
    OPENSSL_free(ret);
    m2_PyBuffer_Release(blob, &buf);
    return obj;
}

PyObject *util_string_to_hex(PyObject *blob) {
    PyObject *obj;
    unsigned char *ret;
    long len;
    Py_buffer buf;

    if (m2_PyObject_GetBuffer(blob, &buf, PyBUF_SIMPLE) == -1)
      return NULL;

    len = buf.len;
    ret = string_to_hex((char *)buf.buf, &len);
    if (ret == NULL) {
        PyErr_SetString(_util_err, ERR_reason_error_string(ERR_get_error()));
        m2_PyBuffer_Release(blob, &buf);
        return NULL;
    }
    obj = PyString_FromStringAndSize((char*)ret, len);
    OPENSSL_free(ret);
    m2_PyBuffer_Release(blob, &buf);
    return obj;
}
%}

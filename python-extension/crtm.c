#include <python2.7/Python.h>
#include <rtm.h>
#include <rtm_internal.h>
#include <rtm_easy.h>

void rtmDestroy(PyObject *capsule) {
    rtm_client_t *rtm = PyCapsule_GetPointer(capsule, "RTM connection");
    if (rtm == NULL)
        return;
    rtm_close(rtm);
    free(rtm);
}

static PyObject *
connect_python(PyObject *self, PyObject *args) {
    rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);
    char *endpoint;
    char *appkey;
    if (!PyArg_ParseTuple(args, "s|s", &endpoint, &appkey))  /* convert Python -> C */
        return NULL;

    if(rtm_easy_connect(rtm, endpoint, appkey) < 0) {
        free(rtm);
        Py_RETURN_NONE;
    }

    return PyCapsule_New(rtm, "RTM connection", rtmDestroy);
}

static PyObject *
subscribe_python(PyObject *self, PyObject *args) {
    char *channel;
    PyObject *capsule;
    unsigned request_id;

    if (!PyArg_ParseTuple(args, "O|s", &capsule, &channel))
        return NULL;

    rtm_client_t *rtm = PyCapsule_GetPointer(capsule, "RTM connection");

    if (rtm_subscribe(rtm, channel, &request_id) < 0) Py_RETURN_NONE;

    return PyInt_FromLong((long)request_id);
}

static PyObject *
publish_python(PyObject *self, PyObject *args) {
    char *channel, *message;
    PyObject *capsule;
    unsigned request_id;

    if (!PyArg_ParseTuple(args, "O|s|s", &capsule, &channel, &message))
        return NULL;

    rtm_client_t *rtm = PyCapsule_GetPointer(capsule, "RTM connection");

    if (rtm_publish_string(rtm, channel, message, &request_id) < 0) Py_RETURN_NONE;

    return PyInt_FromLong((long)request_id);
}

static PyObject *
publish_json_python(PyObject *self, PyObject *args) {
    char *channel, *message;
    PyObject *capsule;
    unsigned request_id;

    if (!PyArg_ParseTuple(args, "O|s|s", &capsule, &channel, &message))
        return NULL;

    rtm_client_t *rtm = PyCapsule_GetPointer(capsule, "RTM connection");

    if (rtm_publish_json(rtm, channel, message, &request_id) < 0) Py_RETURN_NONE;

    return PyInt_FromLong((long)request_id);
}

static PyObject *
recv_python(PyObject *self, PyObject *args) {
    PyObject *capsule;
    rtm_message_list messages;

    if (!PyArg_ParseTuple(args, "O", &capsule))
        return NULL;

    rtm_client_t *rtm = PyCapsule_GetPointer(capsule, "RTM connection");

    if (rtm_easy_recv(rtm, &messages) >= 0) {
        PyObject *results = PyList_New(0);
        rtm_message_list item = messages;

        while (item) {
            PyObject *otmp;
            otmp = Py_BuildValue("{s:i,s:s,s:s}",
                "id", item->request_id,
                "action", item->action,
                "body", item->body);
            PyList_Append(results, otmp);
            item = rtm_easy_next_message(item);
        }
        rtm_easy_free(messages);
        return results;
    } else {
        Py_RETURN_NONE;
    }
}

static PyObject *
close_python(PyObject *self, PyObject *args) {
    PyObject *capsule;

    if (!PyArg_ParseTuple(args, "O", &capsule))
        return NULL;

    rtm_client_t *rtm = PyCapsule_GetPointer(capsule, "RTM connection");
    rtm_close(rtm);

    Py_RETURN_NONE;
}

static PyMethodDef SimpleMethods[] = {
    {"connect",  connect_python, METH_VARARGS, "Connect RTM"},
    {"subscribe",  subscribe_python, METH_VARARGS, "Subscribe to a channel"},
    {"publish_string",  publish_python, METH_VARARGS, "Publish string"},
    {"publish_json",  publish_json_python, METH_VARARGS, "Publish json"},
    {"recv",  recv_python, METH_VARARGS, "Receive events and messages"},
    {"close",  close_python, METH_VARARGS, "Close RTM connection"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initcrtm(void) {
    (void) Py_InitModule("crtm", SimpleMethods);
}

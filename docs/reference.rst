API Reference
=============

.. testsetup::

    import aiosmtplib
    from aiosmtplib import SMTPResponse


The send Coroutine
------------------

Use the :func:`aiosmtplib.send` coroutine in most cases when you want to send a message.

.. autofunction:: aiosmtplib.send


The SMTP Class
--------------

The lower level :class:`aiosmtplib.SMTP` class gives you more control over the SMTP connection.

.. autoclass:: aiosmtplib.SMTP
    :members:
    :inherited-members:

    .. automethod:: aiosmtplib.SMTP.__init__


Server Responses
----------------

.. autoclass:: aiosmtplib.response.SMTPResponse
    :members:


Send Results
------------

``SMTP.sendmail_result`` and ``SMTP.send_message_result`` return a structured
:class:`~aiosmtplib.result.SendResult` describing the outcome of a mail
transaction, including the stage reached, the recipients the server had already
accepted, and whether delivery is confirmed, rejected, incomplete, or
uncertain. On failure the same result is attached to the raised exception as
``send_result``.

.. automodule:: aiosmtplib.result
    :members:
    :show-inheritance:


Status Codes
------------

.. autoclass:: aiosmtplib.typing.SMTPStatus
    :members:
    :undoc-members:


Exceptions
----------

.. automodule:: aiosmtplib.errors
    :members:
    :show-inheritance:

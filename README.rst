=============================
awscli-plugin-credential-mfa
=============================

.. image:: https://img.shields.io/travis/seporaitis/awscli-plugin-credential-mfa/master.svg
        :target: https://travis-ci.org/seporaitis/awscli-plugin-credential-mfa

Automatically asks for MFA token key to retrieve temporary credentials.

Installation and Usage
----------------------

.. code-block:: sh

   python setup.py install
   aws configure set plugins.credentials awscli_plugin_credential_mfa


Assuming your IAM user has `MFA enabled <https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_users-self-manage-mfa-and-creds.html>`_ and credentials set up, you also need to set ``mfa_serial`` and
``source_profile`` in the configuration. Below are instructions for profile ``default``, adjust as
appropriate

.. code-block:: ini

   [default]
   mfa_serial = arn:aws:iam::123456789012:mfa/iam-user-name
   source_profile = default

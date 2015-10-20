import os
import saml2


AUTHENTICATION_BACKENDS += ('djangosaml2.backends.Saml2Backend',)

NODECONDUCTOR_SAML2 = {
    'acs_url': '',
    'attribute_map_civil_number': 'Civil number',
    'attribute_map_dir': os.path.join(conf_dir, 'saml2', 'attribute-maps'),
    'attribute_map_full_name': 'Full name',
    'attribute_map_native_name': 'Native name',
    'debug': False,
    'entity_id': 'saml-sp2',
    'idp_metadata_cert': '',
    'idp_metadata_file': os.path.join(conf_dir, 'saml2', 'idp-metadata.xml'),
    'idp_metadata_url': '',
    'log_file': '',  # empty to disable logging SAML2-related stuff to file
    'log_level': 'INFO',
}

# These shouldn't be configurable by user -- see SAML2 section for details
NODECONDUCTOR_SAML2['cert_file'] = os.path.join(conf_dir, 'saml2', 'dummy.crt'),
NODECONDUCTOR_SAML2['key_file'] = os.path.join(conf_dir, 'saml2', 'dummy.pem')

if NODECONDUCTOR_SAML2['log_file'] != '':
    LOGGING['handlers']['file-saml2'] = {
        'class': 'logging.handlers.WatchedFileHandler',
        'filename': NODECONDUCTOR_SAML2['log_file'],
        'formatter': 'simple',
        'level': NODECONDUCTOR_SAML2['log_level'].upper(),
    }

    LOGGING['loggers']['djangosaml2'] = {
        'handlers': ['file-saml2']
    }

SAML_CONFIG = {
    # full path to the xmlsec1 binary program
    'xmlsec_binary': '/usr/bin/xmlsec1',

    # your entity id, usually your subdomain plus the url to the metadata view
    'entityid': NODECONDUCTOR_SAML2['entity_id'],

    # directory with attribute mapping
    'attribute_map_dir': NODECONDUCTOR_SAML2['attribute_map_dir'],

    # this block states what services we provide
    'service': {
        # we are just a lonely SP
        'sp': {
            'endpoints': {
                # url and binding to the assertion consumer service view
                # do not change the binding or service name
                'assertion_consumer_service': [
                    (NODECONDUCTOR_SAML2['acs_url'], saml2.BINDING_HTTP_POST),
                ],
            },
            'allow_unsolicited': True,  # NOTE: This is the cornerstone! Never set to False

            # attributes that this project needs to identify a user
            'required_attributes': [
                'omanIDCivilNumber',
            ],

            # attributes that may be useful to have but not required
            'optional_attributes': [
                'omancardTitleFullNameEn',
                'omancardTitleFullNameAr',
            ],
        },
    },

    # where the remote metadata is stored
    'metadata': {
        'local': [
            NODECONDUCTOR_SAML2['idp_metadata_file'],
        ],
    },

    # set to 1 to output debugging information
    'debug': int(NODECONDUCTOR_SAML2['debug']),

    # These following files are dummies
    # They are supposed to be valid, but are not really used.
    # They are only used to make PySAML2 happy.
    'key_file': NODECONDUCTOR_SAML2['key_file'],  # private part
    'cert_file': NODECONDUCTOR_SAML2['cert_file'],  # public part

    'only_use_keys_in_metadata': False,
    'allow_unknown_attributes': True,

    'accepted_time_diff': 120,
}

if NODECONDUCTOR_SAML2['idp_metadata_url'] != '':
    SAML_CONFIG['metadata'].update({
        'remote': [
            {
                'url': NODECONDUCTOR_SAML2['idp_metadata_url'],
                'cert': NODECONDUCTOR_SAML2['idp_metadata_cert'],
            }
        ],
    })

SAML_DJANGO_USER_MAIN_ATTRIBUTE = 'civil_number'

SAML_ATTRIBUTE_MAPPING = {
    NODECONDUCTOR_SAML2['attribute_map_civil_number']: ('username', 'civil_number'),
    NODECONDUCTOR_SAML2['attribute_map_full_name']: ('full_name',),
    NODECONDUCTOR_SAML2['attribute_map_native_name']: ('native_name',),
}

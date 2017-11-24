from distutils.core import setup

setup(
        name='PKCS11 Experiments',
        version='0.1dev',
        packages=['softhsm_fun', ],
        license='MIT',
        install_requires=[
            "python-pkcs11",
            ],
)

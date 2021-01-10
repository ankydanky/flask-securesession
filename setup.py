"""
Flask-SecureSession
-------------

Flask-Session is an extension for Flask that adds support for
Server-side Session to your application.

"""
from setuptools import setup


setup(
    name='Flask-SecureSession',
    version='0.3.2',
    url='https://github.com/ankydanky/flask-securesession',
    license='BSD',
    author='NDK',
    author_email='andy@ndk.sytes.net',
    description='Adds encrypted server-side session support to your Flask application',
    long_description=__doc__,
    packages=['flask_securesession'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask>=0.8',
        'cachelib'
    ],
    test_suite='test_session',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)

#!/bin/sh
cp capbac_version.py capbac-client/cli;
cp capbac_version.py capbac-processor/processor;
cp -r capbac-client test/Subject;
cp -r capbac-client test/Issuer;
cp -r capbac-client test/Device;
cp -r capbac-processor test/PDP;

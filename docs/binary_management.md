# Bianry Management

**This document is a work in progess, to describe how files from the VFS are linked to `data/` Document.**

### Attaching binaries

...

### On document suppression

When a document is deleted and it was the last reference to a binary, said binary is deleted as well.

If the binary is meant to be used elsewhere, you should link a binary to another document before deleting the first document.

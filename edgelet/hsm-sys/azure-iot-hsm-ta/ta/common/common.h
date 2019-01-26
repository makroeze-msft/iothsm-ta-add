/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#pragma once

#define CIPHER_VERSION_SIZE_BYTES 1

#define CIPHER_VERSION_V1 1
#define CIPHER_TAG_V1_SIZE_BYTES 16
#define CIPHER_HEADER_V1_SIZE_BYTES ((CIPHER_VERSION_SIZE_BYTES) + (CIPHER_TAG_V1_SIZE_BYTES))

#define MD_OUTPUT_SIZE 32

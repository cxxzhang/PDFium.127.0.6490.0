// Copyright 2024 The PDFium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/fxcodec/data_and_bytes_consumed.h"

#include <utility>

namespace fxcodec {

DataAndBytesConsumed::DataAndBytesConsumed(
    std::unique_ptr<uint8_t, FxFreeDeleter> data,
    uint32_t size,
    uint32_t bytes_consumed)
    : data(std::move(data)), size(size), bytes_consumed(bytes_consumed) {}

DataAndBytesConsumed::DataAndBytesConsumed(DataAndBytesConsumed&&) noexcept =
    default;

DataAndBytesConsumed& DataAndBytesConsumed::operator=(
    DataAndBytesConsumed&&) noexcept = default;

DataAndBytesConsumed::~DataAndBytesConsumed() = default;

}  // namespace fxcodec

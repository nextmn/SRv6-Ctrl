# Copyright Louis Royer and the NextMN contributors. All rights reserved.
# Use of this source code is governed by a MIT-style license that can be
# found in the LICENSE file.
# SPDX-License-Identifier: MIT

FROM golang:1.27.0 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/srv6-ctrl

FROM alpine:3.24.1
RUN apk add --no-cache iptables iproute2
COPY --from=builder /usr/local/bin/srv6-ctrl /usr/local/bin/srv6-ctrl
ENTRYPOINT ["srv6-ctrl"]
CMD ["--help"]
HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=5s --start-interval=100ms \
CMD ["srv6-ctrl", "healthcheck"]

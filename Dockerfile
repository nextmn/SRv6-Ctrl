# Copyright Louis Royer and the NextMN contributors. All rights reserved.
# Use of this source code is governed by a MIT-style license that can be
# found in the LICENSE file.
# SPDX-License-Identifier: MIT

FROM golang:1.27.0 AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 go build -tags urfave_cli_no_template -ldflags="-s -w" -trimpath -o /usr/local/bin/srv6-ctrl

FROM alpine:3.24.1
RUN apk add --no-cache iptables iproute2
COPY --from=builder /usr/local/bin/srv6-ctrl /usr/local/bin/srv6-ctrl
ENTRYPOINT ["srv6-ctrl"]
CMD ["--help"]
HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=5s --start-interval=100ms \
CMD ["srv6-ctrl", "healthcheck"]

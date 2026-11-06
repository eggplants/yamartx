# Built by GoReleaser (dockers_v2). The binary is prebuilt per platform and
# placed at $TARGETPLATFORM/yamartx in the build context.
FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2

ARG TARGETPLATFORM

COPY $TARGETPLATFORM/yamartx /yamartx

ENTRYPOINT ["/yamartx"]

// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QGuiApplication>
#include <QImage>
#include <QPainter>
#include <QSvgRenderer>
#include <QtGlobal>

// silence warnings
static QtMessageHandler mh = qInstallMessageHandler([](QtMsgType, const QMessageLogContext &, const QString &) {});

extern "C" int LLVMFuzzerTestOneInput(const char *Data, size_t Size) {
  static int argc = 3;
  static char arg1[] = "fuzzer";
  static char arg2[] = "-platform";
  static char arg3[] = "minimal";
  static char *argv[] = {arg1, arg2, arg3, nullptr};
  static QGuiApplication qga(argc, argv);
  static QImage image(377, 233, QImage::Format_RGB32);
  static QPainter painter(&image);
  QSvgRenderer renderer(QByteArray::fromRawData(Data, Size));
  renderer.render(&painter);
  return 0;
}

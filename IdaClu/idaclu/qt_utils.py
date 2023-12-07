from idaclu.qt_shims import (
    QCoreApplication,
)


def i18n(text, context="PluginDialog"):
    return QCoreApplication.translate(context, text)

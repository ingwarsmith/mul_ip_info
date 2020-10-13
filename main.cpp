#include "widget.h"
#include <QApplication>
#include <QTranslator>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    auto ru_tr = new QTranslator(&app);
    ru_tr->load(QString(":/res_/ru_translate"));
    app.installTranslator(ru_tr);

    Widget wgt;
    wgt.show();

    return app.exec();
}

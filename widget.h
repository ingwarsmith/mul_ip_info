#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include <QTimer>
#include <QHostInfo>

namespace Ui {
class Widget;
}

class QLineEdit;
class QPushButton;
class QProgressBar;
class QNetworkReply;
class QNetworkAccessManager;

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    ~Widget();

private:
    Ui::Widget *ui;
    QLineEdit   *lned_firstIP;
    QLineEdit   *lned_lastIP;
    QNetworkAccessManager *namgr;
    QPushButton *btn_Scan, *btn_Save;
    QProgressBar *pBar_process;
    QStringList IPs;
    QTimer      tmr;
    QStringList preparedOutTxtLines;
    QString     preparedCurrentLine;

    void        processNext();
    void        restoreGUIaccessed();

private slots:
    void        slotScan();
    void        slotSaveResults();
    void        slotIncrementProgressBar();
    void        slotLookedUpHere(QHostInfo hinf);
    void        slotParseXmlHere(QNetworkReply *reply);
};

#endif // WIDGET_H

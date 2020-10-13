#include "widget.h"
#include "ui_widget.h"

#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QMessageBox>
#include <QProgressBar>
#include <QLabel>

#include <QStringList>
#include <QString>
#include <QFile>
#include <QFileDialog>
#include <QTextStream>

#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QXmlStreamReader>
#include <QNetworkRequest>



Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    QVBoxLayout *lt = new QVBoxLayout;
    setLayout(lt);
    lned_firstIP = new QLineEdit;
    lned_lastIP = new QLineEdit;
    lt->addWidget(new QLabel(tr("Start IP")));
    lt->addWidget(lned_firstIP);
    lt->addWidget(new QLabel(tr("End IP")));
    lt->addWidget(lned_lastIP);
    btn_Scan = new QPushButton(tr("Scan"));
    btn_Save = new QPushButton(tr("Save result"));
    pBar_process = new QProgressBar;
    lt->addWidget(pBar_process);
    pBar_process->setTextVisible(false);
    pBar_process->setMinimum(0);
    pBar_process->setMaximum(100);
    pBar_process->setValue(0);
    pBar_process->setEnabled(false);
    lt->addWidget(btn_Scan);
    lt->addWidget(btn_Save);
    btn_Save->setEnabled(false);
    connect(btn_Scan, SIGNAL(clicked(bool)), this, SLOT(slotScan()));
    connect(btn_Save, SIGNAL(clicked(bool)), this, SLOT(slotSaveResults()));
    connect(&tmr, SIGNAL(timeout()), this, SLOT(slotIncrementProgressBar()));
    tmr.setInterval(200);
    namgr = new QNetworkAccessManager;
    connect(namgr, SIGNAL(finished(QNetworkReply*)), this, SLOT(slotParseXmlHere(QNetworkReply*)));
    this->adjustSize();
    setMinimumWidth(this->height()*3/2);
    setWindowTitle(tr("Scanner of IP-list"));
}

Widget::~Widget()
{
    delete ui;
}

void Widget::processNext()
{
    if (IPs.size() == 0)
    {
        tmr.stop();
        restoreGUIaccessed();
        btn_Save->setEnabled(true);
        return;
    }

    preparedCurrentLine = IPs.takeFirst();

    QHostInfo::lookupHost(preparedCurrentLine, this, SLOT(slotLookedUpHere(QHostInfo)));
}

void Widget::restoreGUIaccessed()
{
    lned_firstIP->setEnabled(true);
    lned_lastIP->setEnabled(true);
    btn_Save->setEnabled(false);
    btn_Scan->setEnabled(true);
    pBar_process->setEnabled(false);
    pBar_process->setValue(0);
}

void Widget::slotScan()
{
    preparedOutTxtLines.clear();
    IPs.clear();
    lned_firstIP->setEnabled(false);
    lned_lastIP->setEnabled(false);
    btn_Save->setEnabled(false);
    btn_Scan->setEnabled(false);
    pBar_process->setEnabled(true);
    auto emptyFirst = lned_firstIP->text().isEmpty(),
            emptyLast = lned_lastIP->text().isEmpty();
    if (emptyFirst||emptyLast)
    {
        QString msg;
        auto both = emptyFirst&&emptyLast;
        if (both)
        {
            msg = tr("Addresses are empty!");
        }
        else
        {
            msg = (emptyFirst ? tr("First") : tr("Second"));
            msg.append(tr(" address is empty!"));
        }
        QMessageBox::critical(this, tr("Error"), msg);
        restoreGUIaccessed();
        return;
    }
    QString frst = lned_firstIP->text(), scnd = lned_lastIP->text();
    QStringList frstlst = frst.split("."), scndlst = scnd.split(".");

    auto frstNot4 = frstlst.size() != 4,
            scndNot4 = scndlst.size() != 4;
    if (frstNot4||scndNot4)
    {
        QString msg;
        auto both = frstNot4&&scndNot4;
        if (both)
        {
            msg = tr("Incorrect IP(s)!");
        }
        else
        {
            msg = (frstNot4 ? frst : scnd).append(tr(" isn't correct IP!"));
        }
        QMessageBox::critical(this, tr("Error"), msg);
        restoreGUIaccessed();
        return;
    }

    auto frstCorrect = true, scndCorrect = true;
    foreach (QString elem, frstlst)
    {
        auto isInt = true;
        elem.toInt(&isInt);
        if (isInt)
        {
            auto value = elem.toInt();
            if (value >= 0 && value < 256)
            {
                //OK
            }
            else
            {
                frstCorrect = false;
            }
        }
        else
        {
            frstCorrect= false;
        }
        if (!frstCorrect)
        {
            break;
        }
    }
    foreach (QString elem, scndlst)
    {
        auto isInt = true;
        elem.toInt(&isInt);
        if (isInt)
        {
            auto value = elem.toInt();
            if (value >= 0 && value < 256)
            {
                //OK
            }
            else
            {
                scndCorrect = false;
            }
        }
        else
        {
            scndCorrect= false;
        }
        if (!scndCorrect)
        {
            break;
        }
    }
    if (!frstCorrect||!scndCorrect)
    {
        QString msg;
        auto both = !frstCorrect&&!scndCorrect;
        if (both)
        {
            msg = tr("Incorrect IP(s)!");
        }
        else
        {
            msg = (!frstCorrect ? frst : scnd).append(tr(" isn't correct IP!"));
        }
        QMessageBox::critical(this, tr("Error"), msg);
        restoreGUIaccessed();
        return;
    }

    auto same = true;
    for (int iElem = 0; iElem < 3; ++iElem)
    {
        same = frstlst.at(iElem) == scndlst.at(iElem);
        if (!same)
        {
            break;
        }
    }
    if (!same)
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("First three elements must be the same for IP-addresses!"));
        restoreGUIaccessed();
        return;
    }

    auto diffCorrect = true;
    auto vFirstStr = frstlst.last(), vLastStr = scndlst.last();
    auto vFirst = vFirstStr.toInt(), vLast = vLastStr.toInt();
    diffCorrect = vFirst <= vLast;
    if (!diffCorrect)
    {
        QMessageBox::critical(this, tr("Error"), tr("Incorrect bounds in range of IP!"));
        restoreGUIaccessed();
        return;
    }

    QStringList preplst = QStringList(frstlst);
    preplst.removeLast();
    preplst.append("");
    QString prep = preplst.join(".");

    for (int i = vFirst; i <= vLast; ++i)
    {
        QString ip = QString::number(i);
        ip.prepend(prep);
        IPs.append(ip);
    }

    tmr.start();

    processNext();
}

void Widget::slotSaveResults()
{
    QString fname = QFileDialog::getSaveFileName(this, tr("Specify the name of saving text file"),
                                                 QString(), "*.txt");
    if (fname.isEmpty())
    {
        return;
    }

    QString extensionMustBe = fname.right(4);
    if (extensionMustBe != ".txt")
        fname.append(".txt");

    QFile fl(fname);
    auto ok = fl.open(QFile::WriteOnly|QFile::Text);
    if (!ok)
    {
        QMessageBox::critical(this, tr("Error"), tr("No wrinting access for file!"));
        return;
    }
    QTextStream streamOut(&fl);

    foreach (QString s, preparedOutTxtLines)
    {
        streamOut << s.append("\n");
    }

    fl.close();
    QStringList tmp = fname.split("/");
    QString fileName_Txt = tmp.takeLast();
    QString fileName_Csv = fileName_Txt;
    fileName_Csv.replace(".txt", ".csv");
    if (fileName_Csv != fileName_Txt)
    {
        tmp.append(fileName_Csv);
        fl.copy(tmp.join("/"));
    }
}

void Widget::slotIncrementProgressBar()
{
    auto value = pBar_process->value();

    if (value == 100)
    {
        value = 0;
    }
    else
    {
        value += 2;
    }
    pBar_process->setValue(value);
}

void Widget::slotLookedUpHere(QHostInfo hinf)
{
    QString nameSite = hinf.hostName();
    if (nameSite == preparedCurrentLine)
        nameSite = "N/A";
    if (!hinf.errorString().isEmpty() && hinf.errorString() != "Unknown error")
        nameSite.append(", ").append(hinf.errorString());

    if (false/*nameSite.contains("N/A")*/)
    {
        QString toFind = preparedCurrentLine;
        preparedCurrentLine.append(";").append(nameSite).append(";");
        //QNetworkRequest rqst(QUrl(toFind.prepend("http://")));
        //namgr->get(rqst);
        //return;
    }
    else
    {
        preparedCurrentLine.append(";").append(nameSite).append(";");
        preparedOutTxtLines << preparedCurrentLine;
        preparedCurrentLine.clear();

        processNext();
    }
}

void Widget::slotParseXmlHere(QNetworkReply *reply)
{
    QString siteTitle = QString();
    QByteArray data = reply->readAll();
    QXmlStreamReader reader;
    reader.addData(data);
    while (!reader.atEnd())
    {
        auto tkntp = reader.readNext();
        if (tkntp == QXmlStreamReader::StartElement
                && reader.name().toString() == QString("title"))
        {
            siteTitle = reader.readElementText();
            break;
        }
    }
    preparedCurrentLine.append(siteTitle);
    preparedOutTxtLines << preparedCurrentLine;
    preparedCurrentLine.clear();

    processNext();
}

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "aes.h"

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_encryptButton_clicked();
    void on_decryptButton_clicked();
    void on_ExitAction_triggered();

private:
    Ui::MainWindow *ui;
    CuteAES *aes;
};
#endif // MAINWINDOW_H

import numpy as np
import csv
import matplotlib.pyplot as plt
import xlrd


def data_process_csv(file_name):
    """
    onDemand process csv data
    """
    new_filename = file_name.split(".")[0]

    exampleFile = open(file_name)
    exampleReader = csv.reader(exampleFile)
    # Get all data from csv
    exampleData = list(exampleReader)
    # Get line and column number
    length_line = len(exampleData)
    length_column = len(exampleData[0])

    for line_num in range(length_line):
        # Usually 1st line is header
        if line_num == 0:
            continue
        # Process data from 2nd line
        for column_num in range(length_column):
            # Process 1st column
            if column_num == 0:
                continue
            else:
                # Process 2nd ....  column
                exampleData[line_num][column_num] = float(exampleData[
                    line_num][column_num]) / 82.0 / 5
    # Write data to new CSV file
    with open(new_filename + "_post.csv", 'w', newline='') as csvfile:
        spamwriter = csv.writer(csvfile, delimiter=',', quotechar=' ')
        for line_num in range(length_line):
            spamwriter.writerow(exampleData[line_num])


def data_process_excel(file_name):
    """
    onDemand process excel data
    """
    new_filename = file_name.split(".")[0]
    xlsx = xlrd.open_workbook(file_name)
    print('All sheets: %s' % xlsx.sheet_names())
    # suppouse we have all data in 1st sheet
    sheet1 = xlsx.sheets()[0]
    sheet1_name = sheet1.name

    length_column = sheet1.ncols
    length_line = sheet1.nrows

    # write new data to file with CSV format
    with open(new_filename + "_post.csv", 'w', newline='') as csvfile:
        spamwriter = csv.writer(csvfile, delimiter=',', quotechar=' ')

        for line_num in range(length_line):
            # Usually 1st line is header
            if line_num == 0:
                spamwriter.writerow(sheet1.row_values(line_num))
                continue
            # Process data from 2nd line
            one_line = []
            for column_num in range(length_column):
                if column_num == 0:
                    one_line.append(sheet1.row(line_num)[column_num].value)
                    # continue
                # elif column_num in [1, 3]:
                #     one_line.append(float(sheet1.row(line_num)[
                #                     column_num].value) / 36.0 / 5)
                else:
                    one_line.append(float(sheet1.row(line_num)[
                                    column_num].value) / 52.0 / 5)
            spamwriter.writerow(one_line)


def one_process(file_name):
    exampleFile = open(file_name)
    exampleReader = csv.reader(exampleFile)
    exampleData = list(exampleReader)
    length_line = len(exampleData)
    fig, (ax1, ax2) = plt.subplots(2, 1)
    fig.subplots_adjust(hspace=0.5)

    server_retran = exampleData[0].index('server_retran')
    server_retran_expected = exampleData[0].index('server_retran_expected')
    client_retran = exampleData[0].index('client_retran')
    client_retran_expected = exampleData[0].index('client_retran_expected')
    x = list()
    server_retran_list = []
    server_retran_expected_list = []
    client_retran_list = []
    client_retran_expected_list = []
    offset_list = []

    for i in range(1, length_line):
        client_retran_val = float(exampleData[i][client_retran])
        client_retran_expected_val = float(
            exampleData[i][client_retran_expected])
        x.append(exampleData[i][0])
        server_retran_list.append(
            format(float(exampleData[i][server_retran]), '.4f'))
        server_retran_expected_list.append(
            format(float(exampleData[i][server_retran_expected]), '.4f'))
        client_retran_list.append(
            format(float(exampleData[i][client_retran]), '.4f'))
        client_retran_expected_list.append(
            format(float(exampleData[i][client_retran_expected]), '.4f'))

    p1 = ax1.plot(
        x, server_retran_list, '.-', color='red', linewidth=1.0
    )
    p2 = ax1.plot(
        x, server_retran_expected_list, '--', color='blue', linewidth=1.0
    )

    p3 = ax2.plot(
        x, client_retran_list, '.-', color='red', linewidth=1.0
    )

    p4 = ax2.plot(
        x, client_retran_expected_list, '--', color='blue', linewidth=1.0
    )

    ax1.set_xlabel('Drop Ratio')
    ax1.set_ylabel('Server Retransmit Ratio')
    ax2.set_xlabel('Drop Ratio')
    ax2.set_ylabel('Client Retransmit Ratio')
    ax1.grid(True)
    ax2.grid(True)
    # ax1.set_ylim(0, 0.04)
    # ax2.set_ylim(0, 0.0)
    plt.savefig('./png/' + file_name.split(".")[0] + '.png')


for csv_file in [
        'eBPF_retransmit_Ratio_Wan_Down_UP_Asym.xls'
]:
    data_process_excel(csv_file)

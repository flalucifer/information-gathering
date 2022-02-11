#!/usr/bin/python
# -*- coding: UTF-8 -*-
from openpyxl.styles import Border, Alignment, Side

border = Border(left=Side(border_style='thin', color='000000'), right=Side(border_style='thin', color='000000'),
                top=Side(border_style='thin', color='000000'), bottom=Side(border_style='thin', color='000000'))
alignment = Alignment(horizontal='center', vertical='center', wrapText=True)
is_exit = False

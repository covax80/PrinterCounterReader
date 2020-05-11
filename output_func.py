def print_table(raw_table = [[]], vertical_delimiter = '|', horizontal_delimiter = '-', cross_delimiter = '+'):
    vertical_delimiter      = '|'
    horizontal_delimiter    = '-'
    cross_delimiter         = '+'


    lens = [0] * len(raw_table[0])
    for row in raw_table:
        for numCol, column in enumerate(row):
            cLen = len(str(column))
            if lens[numCol] < cLen:
                lens[numCol] = cLen

    def spacer( lens ):
        res = '+' + '+'.join( horizontal_delimiter*(x+2) for x in lens ) + '+'
        return res

    def row( lens, row ):
        res = vertical_delimiter
        for num, item in enumerate( row):
            res += ' %s ' % item + ' ' * (lens[num] - len(str(item))) + vertical_delimiter
        return res
    
    res = ""

    for r in raw_table:
        res += spacer(lens) + '\n'
        res += row( lens, r ) + '\n'
    res += spacer(lens) + '\n'
    return res


def html_table(data,title = ""):
    res = """   
<head>
 <title>
       %(title)s
    </title>
      <meta http-equiv="Content-Type" content="text/html; charset=cp1251">
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <!--[if IE]><script type="text/javascript">
      if (/^#__msie303:/.test(window.location.hash))
        window.location.replace(window.location.hash.replace(/^#__msie303:/, '#'));
        </script><![endif]-->
                <link rel="stylesheet" href="tablesorter.css" type="text/css">
        <script type="text/javascript" charset="cp1251" src="jquery.js"></script><style type="text/css"></style>
        <script type="text/javascript" charset="cp1251" src="tablesorter.js"></script>
</head>

<html>
  <h3>%(title)s</h3>
 <table id="myTable" class="tablesorter">
    """%{'title':title}
    res += "<thead>\n\t<tr>"
    for col in data[0]:
        res += "\t\t<th>" + str(col) + "</th>\n"
    res += "\t</tr>\n </thead>\n <tbody>"
    if len(data) > 2:
        for row in data[1:]:
            res += "\t<tr>\n"
            for col in row:
                res += "\t\t<td>" + str(col) + "</td>\n"
            res += "\t</tr>\n"            
    res += " </tbody>\n </table>\n </html>\n"
    return res

if __name__ == '__main__':
    print(print_table(raw_table = [[1,2,3,4,"fadfasdfadfa"], [1,2,4,"fadfasdfadfa",4]]))
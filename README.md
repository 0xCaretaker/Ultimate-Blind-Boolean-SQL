# Ultimate-Blind-Boolean-SQL

- Uses [ffuf](https://github.com/ffuf/ffuf) to automate Blind-based Boolean attacks on the server.
- Try this PortswiggerLab for demo: [Link](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

## Methodology
- Create wordlists to be used for attacks
- Get no. of Databases on the server
- Finds length of each Database name
- Gets Database names
- Similar process for Tables and Column names
- Goes through every Database, Table, Column and counts the no. of respective rows
- Finds the length of each data row
- Dumps every Row content for each Database:Table:Column 

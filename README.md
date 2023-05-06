# Prototype pollution detection
 The implementation of two methods to detect the prototype pollution. One finds the prototype pollution in larger scale by checking if application is parsing the query/hash parameters and the other methods finds the instances of prototype pollution in the code base by doing static analysis
 
 To run the program
 1. Clone the repo
 2. Install selenium package using $pip install selenium
 3. Change the discord webhooks to get the notifications
 4. Run the program using $python pptool.py domain.txt database.csv
 5. After every run, update the domain.txt with the website urls to scan.

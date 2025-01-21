use Easychat;

#create database Easychat;

CREATE TABLE Employees (
    name VARCHAR(255) NOT NULL,
    employee_id INT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE User (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE User_query (
    query_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    user_query TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES User(user_id)
);

INSERT INTO User (email, password)
VALUES
('jawad56461@gmail.com', 'Jawadkhan222'),
('maimoonaa.nasirr@gmail.com', 'Moonanasir'),
('Mustafa.wayne@gmail.com', 'batman123'),
('Pheobe.Khan@gmail.com', 'friends123');


INSERT INTO Employees (name, employee_id, email, password)
VALUES
('Maimoona Nasir', 1001, 'maimoonaa.nasirr@gmail.com', 'Moonanasir'),
('Jawad Ahmed', 1002, 'jawad56461@gmail.com', 'Jawadkhan222'),
('Mustafa Ahmed', 1003, 'Mustafa.wayne@gmail.com', 'batman123');

use Easychat;

select * from User;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    cnic VARCHAR(15) NOT NULL UNIQUE,
    father_name VARCHAR(100) NOT NULL,
    gender ENUM('Male', 'Female', 'Other') NOT NULL,
    country_of_stay VARCHAR(100) NOT NULL,
    address VARCHAR(255) NOT NULL,
    dob DATE NOT NULL,
    cnic_expiry_date DATE NOT NULL,
    address_1 VARCHAR(255),
    address_2 VARCHAR(255),
    account_balance DECIMAL(10, 2) DEFAULT 0.00,
    bnpl_history TEXT,
    account_level ENUM('L0', 'L1', 'Asaan Digital') DEFAULT 'L0',
    iban VARCHAR(34) NOT NULL UNIQUE,
    account_status ENUM('Active', 'Inactive', 'Blocked') DEFAULT 'Active',
    mpin CHAR(5) NOT NULL,
    mobile_number VARCHAR(15) NOT NULL UNIQUE
);

INSERT INTO users (email, password, first_name, last_name, cnic, father_name, gender, country_of_stay, address, dob, cnic_expiry_date, address_1, address_2, account_balance, bnpl_history, account_level, iban, account_status, mpin, mobile_number) VALUES
('jawad56461@gmail.com', 'Jawadkhan222', 'Jawad', 'Khan', '12345-1234567-1', 'Fawad Khan', 'Male', 'Pakistan', '123 Main St, Islamabad', '2003-07-09', '2030-01-15', '123 Main St', 'Apartment 5B', 10000.00, NULL, 'L1', 'PK36XXXX12345678901234567', 'Active', '12345', '0347-8451539'),

('maimoonaa.nasirr@gmail.com', 'Moonanasir', 'Maimoona', 'Nasir', '12345-2345678-2', 'Uncle Nasir', 'Female', 'Pakistan', '456 Park Ave, Lahore', '1982-12-09', '2032-02-20', '456 Park Ave', '', 150.00, NULL, 'L1', 'PK36XXXX12345678901234568', 'Active', '54321', '0347-9999999'),

('Mustafa.wayne@gmail.com', 'batman123', 'Mustafa', 'Ansaar', '12345-3456789-3', 'Uncle Ansaar', 'Male', 'Pakistan', '789 Sunset Blvd, Karachi', '1947-08-14', '2035-03-25', '789 Sunset Blvd', '', 20000.00, NULL, 'L0', 'PK36XXXX12345678901234569', 'Active', '67890', '0302-3456789'),

('1@1.com', '1', 'Noor', 'Jahan', '12345-4567890-4', 'Asif Jahan', 'Female', 'Pakistan', '321 Hilltop Rd, Quetta', '1988-04-30', '2028-04-30', '321 Hilltop Rd', 'Block C', 5000.00, NULL, 'L1', 'PK36XXXX12345678901234570', 'Inactive', '98765', '0303-4567890'),

('2@2.com', '2', 'Faisal', 'Naseem', '12345-5678901-5', 'Bashir Naseem', 'Male', 'Pakistan', '654 Ocean Drive, Peshawar', '1993-05-10', '2033-05-10', '654 Ocean Drive', '', 30000.00, NULL, 'L1', 'PK36XXXX12345678901234571', 'Blocked', '13579', '0304-5678901'),

('3@3.com', '3', 'Zainab', 'Saeed', '12345-6789012-6', 'Irfan Saeed', 'Female', 'Pakistan', '987 Riverbank St, Multan', '1996-06-15', '2036-06-15', '987 Riverbank St', 'Flat 2A', 25000.00, NULL, 'L1', 'PK36XXXX12345678901234572', 'Active', '24680', '0305-6789012');



INSERT INTO User_query (user_id, user_query) VALUES (1, 'What is My account balance');
INSERT INTO User_query (user_id, user_query) VALUES (2, 'What was my last transaction');



select * from Employees;

select * from User;
Describe User;
# HackPark
Bruteforce a websites login with Hydra, identify and use a public exploit then escalate your privileges on this Windows machine!

# Task 1: Deploy the vulnerable Windows machine
## Q1 Whats the name of the clown displayed on the homepage?
simply copy image check in tineye for reference to image. It was from the Steven King movie it, 
Answer: Pennywise

# Task 2: Using hydra to brute force a login
We need to find a login page to attack and identify what type of request the form is making to the webserver. 
Typically, web servers make two types of requests, a GET request which is used to request data from a webserver 
and a POST request which is used to send data to a server.

You can check what request a form is making by right clicking on the login form, inspecting the element and then reading the value in the method field. You can also identify this if you are intercepting the traffic through BurpSuite (other HTTP methods can be found here (opens in new tab)).

## Q1 What request type is the Windows website login form using?
Answer: POST, from quick source check on login page.


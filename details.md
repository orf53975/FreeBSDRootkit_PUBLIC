# Details

## Rootkit (10 marks)

You will provide rootkit.tar which contains install,elevate,log and remote . log and remote can be stub programs if not attempting to obtain bonus marks. rootkit.tar may also include any additional files required to install and run your rootkit.

You are permitted to do anything you wish to achieve the following ___fundamental functionality___

* Provide a method to escalate to uid(0) (root) by a low privileged/non-root user/binary.
* Attempt to hide itself from detection. e.g. concealing itself from kldstat, and userland components from find

Attempts to make a trivial "rootkit" that changes the root password/ only installs a suid binary to do your dirty work will be considered not completing the assignment.

Your rootkit may also have bonus marks awarded for the following functionality. These marks will add to your marks and can go above the maximum mark for the course, such that it will supplement missing marks for any other assignment in the course. These marks will not count towards your pass/fail grade in the exam.

* 2 marks - Provide a method for a remote unauthenticated user to gain network root access.
* 2 marks - Keylog user's input, and exfiltrate the data to an external network
    * This requires monitoring not only physical input, but also SSH input
* 3 marks - Reboot Persistence

Your final rootkit will be marked based on how many other students are able to detect your rootkit.

## Rootkit Midpoint Submission (5 marks)

At the midpoint submission (after 4 weeks) you will be required to submit the following:

* A 2 page design document detailing the functionality of your root kit,
* An elementary implementation of your rootkit that achieves the ___fundamental functionality___

Your design documentation should explain the following:
* How your rootkit installs itself
* How your rootkit provides the privilege escalation functionality
* How your rootkit attempts to conceal itself.
* If you rootkit attempts any bonus marks - How your rootkit will achieve these bonus marks.
* This document should outline in sufficient technical detail your methodology, such that it can be used to write a detection script.
* It is inappropriate that the document merely states "we will hide ourselves from kldstat by modifying a syscall".

This midpoint document should outline all your developments and intention so far. This does not need to be the final design and implementation of your rootkit.
* You may further develop the obfuscation/hiding techniques your rootkit employs after submitting this midpoint.
Your design documentation will be released to the other groups to assist in implementing your detection script.

## Rootkit Detection (10 marks)

Every group will be provided with the design documentation of every other group after the midpoint assessment. The design documents will be released at 12:01pm 30th September 2018 (Sunday of Midsem Break). This should assist in building your rootkit detector.

You will provide detection.tar, which contains detect (your rootkit detector) as well as any other required files to run

You must return status code 0 if no rootkit is detected. And return 1 if a rootkit is detected. You may print whatever output you wish during the script.

* Your detection script will be tested against a variety of clean and infected hosts.
* -2 marks from your detection mark (10 marks) if you detect a false positive (claiming rootkit on a clean host).
    * At least 5 varied configurations of a clean host will be tested.
* +1 mark if you correctly detect a rootkit
* -1 mark if you fail to detect your midpoint rootkit. You are *not* required to detect your final rootkit implementation.
* Minimum mark of 0

## Final Rootkit Writeup (5 marks)

The final deadline will require you to submit a 4+ (at least 4 pages) writeup that details the following:

* Everything required in the midpoint writeup
* What changes were made since the midpoint deadline
* Design decisions for rootkit detection
* What methods are being detected and how
* Design decisions & justifications for rootkit & rootkit detector decisions

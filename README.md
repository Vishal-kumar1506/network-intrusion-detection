# Network Intrusion Detection Using CIC-IDS-2017

**Vishal Kumar**

## Project Overview
This project builds a Network Intrusion Detection System (IDS) using the
CIC-IDS-2017 dataset published by the Canadian Institute for Cybersecurity.
Network traffic is classified as benign or one of 13 cyberattack types
using machine learning models in R.

## Results
- Random Forest OOB Error: 0.2%
- XGBoost Final Error: 0.067%
- ROC AUC: 0.9998

## Repository Structure
- code/ - R code for data cleaning, EDA, preprocessing, and modeling
- reports/ - Final report and contribution statement
- plots/ - All visualizations

## Dataset
CIC-IDS-2017 - Canadian Institute for Cybersecurity
https://www.unb.ca/cic/datasets/ids-2017.html

## Technologies Used
R, randomForest, xgboost, caret, ggplot2, pROC

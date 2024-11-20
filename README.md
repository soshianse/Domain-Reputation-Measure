# Domain Reputation Measure 
This project aims to develop a comprehensive measure for domain reputation by leveraging a variety of data sources and relationship mappings of unique identifiers in multiple contexts such as DNS records, WHOIS records, BGP activities, and IP/ASN registration data. 

The measure provides a real-time ranking of domain reputations that can be queried per domain or aggregated based on identifiers like IP addresses or autonomous system numbers (ASNs). 
## Table of Contents 
  - [Introduction](#introduction)
  - [Components](#components)
  - [Technical Implementation](#technical-implementation)
  - [Usage](#usage)
  - [Contributing](#contributing)
  - [License](#license)

## Introduction 
The objective is to provide up-to-date reputational assessments reflecting the current state and recent changes in domain infrastructure. This tool can help identify domains that may pose security risks due to suspicious activities like frequent network changes or recent registrations. 

## Components 
The domain reputation measure comprises several components: 
  1. **Tranco Top Million List History (Past 100 Days):**
     - Tracks daily presence and ranking changes of domains.
  2. **BGP Announced Networks:**
     - Analyzes changes in announced networks (IP prefixes) and assigns weight based on recency.
  3. **Domain Registration Date:**
     - Considers domain age and scrutinizes recently registered domains more rigorously.
  4. **IP Address Ownership Data:**
     - Examines IP registration dates and ownership changes, emphasizing recent changes.
  5. **Relationship Mapping of Unique Identifiers:**
     - Maps domains to IP addresses, WHOIS records, and BGP activities to assess infrastructure health.
     -
## Technical Implementation 
The implementation involves several key steps: 
  - **Data Collection:** Gather data from Tranco lists, DNS records, BGP announcements, and WHOIS databases.
  - **Data Processing:** Analyze rank trends, BGP activities, and registration data to compute reputation scores.
  - **Score Calculation:** Use a composite scoring system to assign reputation scores based on weighted components.
  - **Real-Time Ranking:** Set up a system for real-time updates and scalable data processing.

## Usage
To use this project, clone the repository and follow the setup instructions:

```bash git clone https://github.com/yourusername/domain-reputation-measure.git cd domain-reputation-measure ``` 

Run the main script to start data collection and processing: 

```bash python main.py ```

For more detailed usage instructions, refer to the `docs` directory.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes. Make sure to update tests as appropriate.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. ``` 
 

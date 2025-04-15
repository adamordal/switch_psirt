# Cisco Vulnerability Dashboard

This project is a Streamlit-based application for visualizing Cisco switch vulnerabilities. It integrates with Cisco PSIRT API to fetch vulnerability data and uses OpenAI's GPT to generate executive summaries.

---

## File Structure

```
\openai\
    ├── app3.py          # Main Streamlit app
    ├── cisco_api.py     # Cisco API-related functions
    ├── dnac_inventory.py # Cisco DNA Center inventory functions
    ├── gpt_utils.py     # GPT-related functions
    ├── utils.py         # General utility functions
```

---

## File Descriptions

### `app3.py`

This is the main entry point for the Streamlit application. It handles the user interface, inventory loading, and visualization of vulnerabilities.

Key Features:
- Mock inventory for testing.
- Upload functionality for custom inventory JSON files.
- Integration with Cisco PSIRT API for vulnerability correlation.
- Integration with Cisco DNA Center for inventory retrieval.
- GPT-generated executive summaries.
- Interactive charts and filters for exploring vulnerabilities.

---

### `cisco_api.py`

Contains functions for interacting with the Cisco PSIRT API.

Key Functions:
- `get_psirt_token(client_id, client_secret)`: Retrieves an OAuth2 token for authentication.
- `get_vulns_for_version(version, token)`: Fetches vulnerability advisories for a specific software version.
- `correlate_vulnerabilities(inventory, token)`: Matches devices in the inventory with known vulnerabilities.

---

### `dnac_inventory.py`

Handles inventory retrieval from Cisco DNA Center.

Key Functions:
- `load_inventory_from_dnac()`: Loads the device inventory from Cisco DNA Center, including configurations.
- `get_dnac_token()`: Retrieves an authentication token for Cisco DNA Center.
- `get_all_devices(token)`: Fetches all devices from Cisco DNA Center.
- `fetch_all_configs(devices, token)`: Retrieves configuration data for all devices.

---

### `gpt_utils.py`

Handles GPT-related functionality for generating summaries.

Key Functions:
- `summarize_with_gpt(inventory_summary, top_n=10)`: Generates an executive summary of the top N riskiest devices using GPT.

---

### `utils.py`

Contains general utility functions and constants.

Key Features:
- `calculate_risk(vulns)`: Calculates a risk score based on the severity of vulnerabilities.
- `build_chart_data(matches)`: Prepares data for visualizing vulnerabilities by severity.
- `render_chart(df)`: Renders a bar chart of vulnerabilities by severity.
- `render_filtered_devices(matches)`: Displays devices filtered by vulnerability severity.
- `render_full_device_list(matches)`: Displays a detailed list of vulnerabilities for all devices.

---

## How to Run

1. Install the required dependencies:
   ```bash
   pip install streamlit pandas plotly openai requests aiohttp
   ```

2. Set the required environment variables:
   - `OPENAI_API_KEY`: Your OpenAI API key.
   - `CISCO_CLIENT_ID`: Cisco API client ID.
   - `CISCO_CLIENT_SECRET`: Cisco API client secret.
   - `DNAC_HOST`: Cisco DNA Center host URL.
   - `DNAC_USER`: Cisco DNA Center username.
   - `DNAC_PASS`: Cisco DNA Center password.

3. Run the Streamlit app:
   ```bash
   streamlit run app3.py
   ```

4. Open the app in your browser and explore the dashboard.

---

## Example Usage

- **Mock Inventory**: Use the mock inventory to test the app without uploading a file.
- **Upload Inventory**: Upload a JSON file containing device inventory to analyze vulnerabilities.
- **Cisco DNA Center Integration**: Automatically retrieve inventory and configurations from Cisco DNA Center.
- **Executive Summary**: View GPT-generated summaries for the riskiest devices.
- **Charts and Filters**: Explore vulnerabilities by severity using interactive charts and filters.

---

## Features

- **Cisco PSIRT Integration**: Automatically fetch vulnerability data for Cisco devices.
- **Cisco DNA Center Integration**: Retrieve inventory and configurations directly from Cisco DNA Center.
- **GPT Summaries**: Generate concise executive summaries for decision-making.
- **Interactive Visualizations**: View and filter vulnerabilities by severity.
- **Customizable Inventory**: Use mock data, upload your own inventory, or retrieve it from Cisco DNA Center.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.
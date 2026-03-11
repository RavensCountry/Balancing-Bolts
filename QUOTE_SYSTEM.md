# Quote Fetching System

The Balancing Bolts quote system can operate in two modes: **Real Mode** (web scraping) and **Demo Mode** (mock data).

## How It Works

### Automatic Mode Selection

1. **Real Mode** - Uses Selenium browser automation to fetch actual prices from vendor websites
   - Requires Chrome, Firefox, or Edge to be installed
   - Logs into vendor accounts using stored credentials
   - Scrapes real product prices, availability, and SKUs
   - Slower (5-15 seconds per vendor)

2. **Demo Mode** - Returns simulated pricing data
   - No browser required
   - Works immediately in any environment
   - Returns realistic mock prices based on item keywords
   - Fast (instant response)

### Mode Selection Logic

The system automatically chooses the appropriate mode:

```
IF FORCE_DEMO_MODE = true THEN
    → Use Demo Mode
ELSE
    TRY to initialize browser (Chrome → Firefox → Edge)
        IF browser available THEN
            TRY to scrape vendor website
                IF scraping succeeds AND returns data THEN
                    → Use Real Mode
                ELSE
                    → Fall back to Demo Mode
            CATCH any errors
                → Fall back to Demo Mode
        ELSE
            → Use Demo Mode
END
```

## Environment Variables

### `FORCE_DEMO_MODE`
- **Default**: `false`
- **Options**: `true` or `false`
- **Description**: When `true`, always use demo mode (skip browser automation entirely)
- **Example**: `export FORCE_DEMO_MODE=true`

### `PREFERRED_BROWSER`
- **Default**: `chrome,firefox,edge`
- **Description**: Comma-separated list of browsers to try (in order)
- **Example**: `export PREFERRED_BROWSER=firefox,chrome,edge`

### `VENDOR_ENCRYPTION_KEY`
- **Description**: Encryption key for vendor credentials
- **Note**: Auto-generated if not provided

## Usage Scenarios

### Development (No Browser Installed)
```bash
# No environment variables needed
# System automatically falls back to demo mode
```

### Development (Force Demo Mode)
```bash
export FORCE_DEMO_MODE=true
# Always uses demo mode, even if browser is available
```

### Production (Real Vendor Scraping)
```bash
# Ensure Chrome/Firefox/Edge is installed
# Configure vendor credentials in the UI
# System will automatically use real scraping
```

### Production (Prefer Firefox)
```bash
export PREFERRED_BROWSER=firefox,chrome,edge
# Tries Firefox first, then Chrome, then Edge
```

## Supported Vendors

### Home Depot
- **Base URL**: https://www.homedepot.com
- **Demo Prices**: $3.99 - $199.00 (based on item keywords)
- **Real Scraping**: Extracts price, SKU, availability from product search

### Lowe's
- **Base URL**: https://www.lowes.com
- **Demo Prices**: $3.79 - $189.00 (based on item keywords)
- **Real Scraping**: Extracts price, item number, availability from product search

### Grainger
- **Base URL**: https://www.grainger.com
- **Demo Prices**: $4.99 - $229.00 (based on item keywords)
- **Real Scraping**: Extracts price, Grainger ID, shipping time from product search

## Demo Price Keywords

The demo mode uses keyword matching to provide realistic pricing:

| Keyword | Home Depot | Lowe's | Grainger |
|---------|-----------|--------|----------|
| bleach | $3.99 | $3.79 | $4.99 |
| battery | $6.99 | $7.49 | $8.99 |
| cleaning | $7.49 | $6.99 | $9.49 |
| light | $8.97 | $9.48 | $11.99 |
| bulb | $12.49 | $11.98 | $15.49 |
| outdoor | $12.99 | $11.99 | $14.99 |
| led | $15.99 | $14.99 | $19.99 |
| lock | $19.97 | $18.97 | $24.97 |
| filter | $24.99 | $23.97 | $29.99 |
| paint | $34.98 | $32.98 | $39.98 |
| faucet | $89.99 | $84.99 | $109.99 |
| door | $199.00 | $189.00 | $229.00 |
| default | $25.00 | $24.00 | $28.00 |

## Vendor Credentials

To enable real scraping, add vendor credentials in the UI:

1. Navigate to **Quotes** → **Manage Vendor Logins**
2. Add credentials for each vendor:
   - Vendor Name (e.g., "Home Depot", "Lowe's", "Grainger")
   - Username (your vendor account email)
   - Password (encrypted automatically)
3. Mark credentials as active

**Note**: Without configured credentials, the system runs in demo mode.

## Troubleshooting

### "No quotes available"
- **Cause**: Browser automation failed AND demo mode didn't return data
- **Fix**: Ensure `_get_demo_quote()` is implemented for all vendor classes

### "0 quotes" but status is "COMPLETED"
- **Cause**: All vendor fetchers returned empty arrays
- **Fix**: Check logs for specific errors, verify demo price keywords

### Slow quote fetching
- **Cause**: Using real browser automation
- **Fix**: Set `FORCE_DEMO_MODE=true` for faster demo quotes

### Browser errors in logs
- **Cause**: Trying real scraping without Chrome/Firefox/Edge
- **Fix**: Install a browser OR set `FORCE_DEMO_MODE=true`

## Logging

The system logs mode selection for transparency:

```
INFO: FORCE_DEMO_MODE enabled - returning demo quote for outdoor bleach
INFO: Successfully fetched real quote for light bulb
WARNING: Browser not available, returning demo data: Failed to initialize any browser
WARNING: Real scraping returned no results, using demo data for xyz
ERROR: Error getting quote, falling back to demo data: TimeoutException
```

## Best Practices

1. **Development**: Use `FORCE_DEMO_MODE=true` for fast iteration
2. **Staging**: Test with real scraping to verify vendor website compatibility
3. **Production**: Use real scraping with proper vendor credentials
4. **Monitoring**: Check logs to see when demo vs real mode is used
5. **Graceful Degradation**: System always returns quotes, even if scraping fails

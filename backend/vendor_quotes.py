"""
Vendor quote pulling service
Handles automated login and price fetching from vendor websites
"""
import os
import json
import asyncio
from typing import List, Dict, Optional
from datetime import datetime
from cryptography.fernet import Fernet
import requests
from bs4 import BeautifulSoup

# Encryption key for storing passwords securely
# In production, store this in environment variables
ENCRYPTION_KEY = os.getenv('VENDOR_ENCRYPTION_KEY', Fernet.generate_key())
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_password(password: str) -> str:
    """Encrypt a password for secure storage"""
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a stored password"""
    return cipher.decrypt(encrypted_password.encode()).decode()

class VendorQuoteFetcher:
    """Base class for vendor-specific quote fetchers"""

    def __init__(self, username: str, encrypted_password: str):
        self.username = username
        self.password = decrypt_password(encrypted_password)
        self.session = requests.Session()
        self.is_logged_in = False

    async def login(self) -> bool:
        """Login to vendor website - override in subclasses"""
        raise NotImplementedError

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search for products - override in subclasses"""
        raise NotImplementedError

    async def get_quote(self, item_description: str, quantity: int = 1) -> List[Dict]:
        """Get quotes for an item"""
        if not self.is_logged_in:
            await self.login()

        return await self.search_product(item_description, quantity)


class HomeDepotQuoteFetcher(VendorQuoteFetcher):
    """Home Depot specific implementation"""

    BASE_URL = "https://www.homedepot.com"

    async def login(self) -> bool:
        """Login to Home Depot"""
        # Note: This is a placeholder implementation
        # Real implementation would need to handle Home Depot's actual login flow
        try:
            # Home Depot Pro/Business account login
            login_url = f"{self.BASE_URL}/auth/view/signin"
            # Implementation would go here
            self.is_logged_in = True
            return True
        except Exception as e:
            print(f"Home Depot login failed: {e}")
            return False

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search Home Depot for products"""
        try:
            # Placeholder for actual API/scraping implementation
            search_url = f"{self.BASE_URL}/s/{query}"
            # Would parse results and return structured data
            return []
        except Exception as e:
            print(f"Home Depot search failed: {e}")
            return []


class LowesQuoteFetcher(VendorQuoteFetcher):
    """Lowe's specific implementation"""

    BASE_URL = "https://www.lowes.com"

    async def login(self) -> bool:
        """Login to Lowe's"""
        try:
            # Lowe's for Pros account login
            self.is_logged_in = True
            return True
        except Exception as e:
            print(f"Lowe's login failed: {e}")
            return False

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search Lowe's for products"""
        try:
            # Placeholder for actual implementation
            return []
        except Exception as e:
            print(f"Lowe's search failed: {e}")
            return []


class GraingerQuoteFetcher(VendorQuoteFetcher):
    """Grainger specific implementation"""

    BASE_URL = "https://www.grainger.com"

    async def login(self) -> bool:
        """Login to Grainger"""
        try:
            # Grainger account login
            self.is_logged_in = True
            return True
        except Exception as e:
            print(f"Grainger login failed: {e}")
            return False

    async def search_product(self, query: str, quantity: int = 1) -> List[Dict]:
        """Search Grainger for products"""
        try:
            # Placeholder for actual implementation
            return []
        except Exception as e:
            print(f"Grainger search failed: {e}")
            return []


# Factory to get the right fetcher for a vendor
VENDOR_FETCHERS = {
    "Home Depot": HomeDepotQuoteFetcher,
    "Lowe's": LowesQuoteFetcher,
    "Grainger": GraingerQuoteFetcher,
}

def get_vendor_fetcher(vendor_name: str, username: str, encrypted_password: str) -> Optional[VendorQuoteFetcher]:
    """Get the appropriate fetcher for a vendor"""
    fetcher_class = VENDOR_FETCHERS.get(vendor_name)
    if fetcher_class:
        return fetcher_class(username, encrypted_password)
    return None


async def fetch_quotes_from_vendors(
    item_description: str,
    quantity: int,
    vendor_credentials: List[Dict]
) -> List[Dict]:
    """
    Fetch quotes from multiple vendors concurrently

    Args:
        item_description: What to search for
        quantity: How many
        vendor_credentials: List of {vendor_name, username, encrypted_password}

    Returns:
        List of quote dictionaries
    """
    tasks = []

    for cred in vendor_credentials:
        fetcher = get_vendor_fetcher(
            cred['vendor_name'],
            cred['username'],
            cred['encrypted_password']
        )

        if fetcher:
            tasks.append(fetcher.get_quote(item_description, quantity))

    # Run all fetchers concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Flatten results and filter out errors
    quotes = []
    for result in results:
        if isinstance(result, list):
            quotes.extend(result)

    return quotes


def generate_email_html(quote_request: Dict, quotes: List[Dict]) -> str:
    """
    Generate email-ready HTML for quotes

    Args:
        quote_request: {item_description, quantity, property_name, etc.}
        quotes: List of quote dictionaries

    Returns:
        HTML string ready for email
    """
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }}
            .header {{
                background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%);
                color: white;
                padding: 30px;
                border-radius: 8px;
                margin-bottom: 30px;
            }}
            .header h1 {{
                margin: 0 0 10px 0;
                font-size: 28px;
            }}
            .header p {{
                margin: 0;
                opacity: 0.9;
            }}
            .request-details {{
                background: #f8fafc;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 30px;
                border-left: 4px solid #4f46e5;
            }}
            .request-details h2 {{
                margin-top: 0;
                color: #4f46e5;
            }}
            .detail-row {{
                margin: 10px 0;
            }}
            .detail-label {{
                font-weight: bold;
                color: #64748b;
            }}
            .quotes-container {{
                margin-top: 30px;
            }}
            .quote-card {{
                background: white;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }}
            .quote-vendor {{
                font-size: 20px;
                font-weight: bold;
                color: #1e293b;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            .quote-price {{
                font-size: 28px;
                color: #10b981;
                font-weight: bold;
            }}
            .quote-details {{
                margin-top: 15px;
                padding-top: 15px;
                border-top: 1px solid #e2e8f0;
            }}
            .quote-row {{
                display: flex;
                justify-content: space-between;
                margin: 8px 0;
                font-size: 14px;
            }}
            .quote-label {{
                color: #64748b;
            }}
            .quote-value {{
                font-weight: 500;
                color: #1e293b;
            }}
            .quote-link {{
                display: inline-block;
                margin-top: 15px;
                padding: 10px 20px;
                background: #4f46e5;
                color: white;
                text-decoration: none;
                border-radius: 6px;
                font-size: 14px;
            }}
            .quote-link:hover {{
                background: #4338ca;
            }}
            .best-price {{
                background: #d1fae5;
                border-color: #10b981;
            }}
            .best-price .quote-vendor::after {{
                content: "BEST PRICE";
                font-size: 12px;
                background: #10b981;
                color: white;
                padding: 4px 12px;
                border-radius: 20px;
            }}
            .footer {{
                margin-top: 40px;
                padding-top: 20px;
                border-top: 2px solid #e2e8f0;
                text-align: center;
                color: #64748b;
                font-size: 14px;
            }}
            .summary-table {{
                width: 100%;
                margin-top: 20px;
                border-collapse: collapse;
            }}
            .summary-table th {{
                background: #f1f5f9;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #475569;
                border-bottom: 2px solid #e2e8f0;
            }}
            .summary-table td {{
                padding: 12px;
                border-bottom: 1px solid #e2e8f0;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🏢 Balancing Bolts Quote Comparison</h1>
            <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>

        <div class="request-details">
            <h2>Quote Request Details</h2>
            <div class="detail-row">
                <span class="detail-label">Item:</span> {quote_request.get('item_description', 'N/A')}
            </div>
            <div class="detail-row">
                <span class="detail-label">Quantity:</span> {quote_request.get('quantity', 1)}
            </div>
            <div class="detail-row">
                <span class="detail-label">Property:</span> {quote_request.get('property_name', 'N/A')}
            </div>
            <div class="detail-row">
                <span class="detail-label">Requested by:</span> {quote_request.get('user_name', 'N/A')}
            </div>
        </div>

        <div class="quotes-container">
            <h2>Price Comparison ({len(quotes)} vendors)</h2>
    """

    # Sort quotes by total price to identify best price
    sorted_quotes = sorted(quotes, key=lambda q: q.get('total_price', float('inf')))

    for i, quote in enumerate(sorted_quotes):
        best_class = ' best-price' if i == 0 and len(sorted_quotes) > 1 else ''

        html += f"""
            <div class="quote-card{best_class}">
                <div class="quote-vendor">
                    <span>{quote.get('vendor_name', 'Unknown Vendor')}</span>
                    <span class="quote-price">${quote.get('total_price', 0):.2f}</span>
                </div>
                <div class="quote-details">
                    <div class="quote-row">
                        <span class="quote-label">Product:</span>
                        <span class="quote-value">{quote.get('item_name', 'N/A')}</span>
                    </div>
                    <div class="quote-row">
                        <span class="quote-label">Unit Price:</span>
                        <span class="quote-value">${quote.get('unit_price', 0):.2f}</span>
                    </div>
                    <div class="quote-row">
                        <span class="quote-label">Quantity:</span>
                        <span class="quote-value">{quote.get('quantity', 1)}</span>
                    </div>
        """

        if quote.get('vendor_item_number'):
            html += f"""
                    <div class="quote-row">
                        <span class="quote-label">Item #:</span>
                        <span class="quote-value">{quote['vendor_item_number']}</span>
                    </div>
            """

        if quote.get('availability'):
            html += f"""
                    <div class="quote-row">
                        <span class="quote-label">Availability:</span>
                        <span class="quote-value">{quote['availability']}</span>
                    </div>
            """

        if quote.get('vendor_url'):
            html += f"""
                    <a href="{quote['vendor_url']}" class="quote-link" target="_blank">View on {quote.get('vendor_name')}</a>
            """

        html += """
                </div>
            </div>
        """

    # Add summary table
    html += """
        <h2 style="margin-top: 40px;">Summary</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Vendor</th>
                    <th>Unit Price</th>
                    <th>Total</th>
                    <th>Savings vs. Highest</th>
                </tr>
            </thead>
            <tbody>
    """

    if sorted_quotes:
        highest_price = sorted_quotes[-1].get('total_price', 0)
        for quote in sorted_quotes:
            total = quote.get('total_price', 0)
            savings = highest_price - total
            savings_pct = (savings / highest_price * 100) if highest_price > 0 else 0

            html += f"""
                <tr>
                    <td><strong>{quote.get('vendor_name', 'Unknown')}</strong></td>
                    <td>${quote.get('unit_price', 0):.2f}</td>
                    <td><strong>${total:.2f}</strong></td>
                    <td>${savings:.2f} ({savings_pct:.1f}%)</td>
                </tr>
            """

    html += """
            </tbody>
        </table>

        <div class="footer">
            <p><strong>Balancing Bolts</strong> - Apartment Inventory Management System</p>
            <p>This quote comparison was generated automatically from vendor websites.</p>
            <p style="margin-top: 10px; font-size: 12px;">
                Prices and availability are subject to change. Please verify with vendors before purchasing.
            </p>
        </div>
    </body>
    </html>
    """

    return html

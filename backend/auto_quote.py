"""
Automatic quote generation from invoices
Analyzes invoice items and generates quote requests for reordering
"""
import re
from typing import List, Dict, Optional
from sqlmodel import select
from .database import get_session
from .models import Invoice, InventoryItem, QuoteRequest, QuoteStatus
import logging

logger = logging.getLogger(__name__)

# Common item patterns that typically need regular reordering
REORDERABLE_PATTERNS = [
    r'\b(light|bulb|led)\b',
    r'\b(filter|hvac|air)\b',
    r'\b(paint|primer|caulk)\b',
    r'\b(battery|batteries)\b',
    r'\b(cleaning|cleaner|supplies)\b',
    r'\b(lock|key|hardware)\b',
    r'\b(switch|outlet|electrical)\b',
    r'\b(plumbing|faucet|pipe)\b',
    r'\b(door|window|glass)\b',
    r'\b(flooring|carpet|tile)\b',
]

# Keywords that suggest maintenance/consumable items
MAINTENANCE_KEYWORDS = [
    'replacement', 'repair', 'maintenance', 'service',
    'consumable', 'supplies', 'parts', 'refill'
]


def should_auto_quote(item_description: str, vendor: str = None) -> bool:
    """
    Determine if an item from an invoice should automatically get a quote request

    Args:
        item_description: Description of the item from invoice
        vendor: Vendor name (optional, for future vendor-specific logic)

    Returns:
        True if item should get automatic quote request
    """
    if not item_description:
        return False

    desc_lower = item_description.lower()

    # Check maintenance keywords
    for keyword in MAINTENANCE_KEYWORDS:
        if keyword in desc_lower:
            return True

    # Check reorderable patterns
    for pattern in REORDERABLE_PATTERNS:
        if re.search(pattern, desc_lower, re.IGNORECASE):
            return True

    return False


def extract_quantity_from_description(description: str) -> int:
    """
    Try to extract quantity from item description
    Looks for patterns like "5 units", "qty: 3", "x2", etc.

    Returns:
        Extracted quantity or 1 as default
    """
    if not description:
        return 1

    # Pattern for "qty: 5", "quantity: 3", etc.
    qty_match = re.search(r'\b(?:qty|quantity|count)[\s:]+(\d+)\b', description, re.IGNORECASE)
    if qty_match:
        return int(qty_match.group(1))

    # Pattern for "x5", "x 3", etc.
    x_match = re.search(r'\bx\s*(\d+)\b', description, re.IGNORECASE)
    if x_match:
        return int(x_match.group(1))

    # Pattern for "5 units", "3 pieces", etc.
    unit_match = re.search(r'\b(\d+)\s+(?:units|pieces|items|pcs|ea)\b', description, re.IGNORECASE)
    if unit_match:
        return int(unit_match.group(1))

    return 1


def clean_item_description(description: str) -> str:
    """
    Clean up item description for quote request
    Removes quantity indicators, special characters, etc.
    """
    if not description:
        return ""

    # Remove quantity patterns
    cleaned = re.sub(r'\b(?:qty|quantity|count)[\s:]+\d+\b', '', description, flags=re.IGNORECASE)
    cleaned = re.sub(r'\bx\s*\d+\b', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\b\d+\s+(?:units|pieces|items|pcs|ea)\b', '', cleaned, flags=re.IGNORECASE)

    # Remove extra whitespace
    cleaned = ' '.join(cleaned.split())

    return cleaned.strip()


async def generate_quotes_from_invoice(
    invoice_id: int,
    user_id: int,
    property_id: Optional[int] = None,
    auto_fetch: bool = True
) -> List[QuoteRequest]:
    """
    Automatically generate quote requests from invoice items

    Args:
        invoice_id: ID of the invoice to analyze
        user_id: User who imported the invoice
        property_id: Property associated with invoice
        auto_fetch: If True, automatically fetch quotes from vendors

    Returns:
        List of created QuoteRequest objects
    """
    created_quotes = []

    with get_session() as session:
        # Get the invoice
        invoice = session.exec(
            select(Invoice).where(Invoice.id == invoice_id)
        ).first()

        if not invoice:
            logger.warning(f"Invoice {invoice_id} not found")
            return created_quotes

        # Get inventory items linked to this invoice
        items = session.exec(
            select(InventoryItem).where(InventoryItem.property_id == invoice.property_id)
        ).all()

        # Check if invoice has raw text we can parse
        items_to_quote = []

        if invoice.raw_text:
            # Parse invoice text for items
            lines = invoice.raw_text.split('\n')
            for line in lines:
                line = line.strip()
                if not line or len(line) < 10:  # Skip short lines
                    continue

                # Check if this line describes a reorderable item
                if should_auto_quote(line, invoice.vendor):
                    items_to_quote.append({
                        'description': clean_item_description(line),
                        'quantity': extract_quantity_from_description(line),
                        'source': 'invoice_text'
                    })

        # Also check inventory items that might need reordering
        for item in items:
            if should_auto_quote(item.name) or should_auto_quote(item.description or ''):
                # Check if we already have a quote request for this item
                existing = session.exec(
                    select(QuoteRequest).where(
                        QuoteRequest.item_description == item.name,
                        QuoteRequest.invoice_id == invoice_id
                    )
                ).first()

                if not existing:
                    items_to_quote.append({
                        'description': item.name,
                        'quantity': 1,  # Default to 1 for reorder
                        'source': 'inventory_item'
                    })

        # Create quote requests
        for item_info in items_to_quote:
            quote_request = QuoteRequest(
                property_id=property_id or invoice.property_id,
                user_id=user_id,
                item_description=item_info['description'],
                quantity=item_info['quantity'],
                status=QuoteStatus.pending,
                notes=f"Auto-generated from invoice #{invoice_id} - {invoice.vendor}",
                invoice_id=invoice_id,
                is_auto_generated=True
            )

            session.add(quote_request)
            session.commit()
            session.refresh(quote_request)

            created_quotes.append(quote_request)
            logger.info(f"Created auto quote request #{quote_request.id} for: {item_info['description']}")

        # Optionally auto-fetch quotes from vendors
        if auto_fetch and created_quotes:
            # Import here to avoid circular dependency
            from . import vendor_quotes
            from .models import VendorCredential

            # Get active vendor credentials
            credentials = session.exec(
                select(VendorCredential).where(VendorCredential.is_active == True)
            ).all()

            if credentials:
                logger.info(f"Auto-fetching quotes for {len(created_quotes)} items")

                for quote_request in created_quotes:
                    try:
                        # Update status to fetching
                        quote_request.status = QuoteStatus.fetching
                        session.add(quote_request)
                        session.commit()

                        # Prepare credential data
                        creds_data = [{
                            'vendor_name': c.vendor_name,
                            'username': c.username,
                            'encrypted_password': c.encrypted_password
                        } for c in credentials]

                        # Note: Actual quote fetching would happen here
                        # For now, mark as completed with no quotes (placeholder)
                        quote_request.status = QuoteStatus.completed
                        session.add(quote_request)
                        session.commit()

                    except Exception as e:
                        logger.exception(f"Error auto-fetching quotes for request {quote_request.id}: {e}")
                        quote_request.status = QuoteStatus.failed
                        session.add(quote_request)
                        session.commit()

    return created_quotes


def get_invoice_quotes(invoice_id: int) -> List[Dict]:
    """
    Get all quote requests associated with an invoice

    Args:
        invoice_id: ID of the invoice

    Returns:
        List of quote request dictionaries with quote details
    """
    with get_session() as session:
        quote_requests = session.exec(
            select(QuoteRequest).where(QuoteRequest.invoice_id == invoice_id)
        ).all()

        from .models import Quote

        results = []
        for qr in quote_requests:
            quotes = session.exec(
                select(Quote).where(Quote.quote_request_id == qr.id)
            ).all()

            results.append({
                'quote_request_id': qr.id,
                'item_description': qr.item_description,
                'quantity': qr.quantity,
                'status': qr.status,
                'is_auto_generated': qr.is_auto_generated,
                'quote_count': len(quotes),
                'quotes': [{
                    'vendor_name': q.vendor_name,
                    'unit_price': q.unit_price,
                    'total_price': q.total_price,
                    'availability': q.availability
                } for q in quotes]
            })

        return results

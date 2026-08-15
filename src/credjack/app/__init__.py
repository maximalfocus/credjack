"""The Beacon check applications: one shared service layer, three entry points.

The secure, vulnerable, and naive applications share this layer and differ only in how the
fetch target is validated and how redirects and address resolution are handled. This slice
delivers the shared layer plus the secure entry point.
"""

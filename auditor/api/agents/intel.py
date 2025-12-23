from .utils import supabase, embeddings

def brain_intel(search_terms: list):
    """
    Step 2: The Retrieval.
    Uses Local Embeddings to find the exact Policy ID in Supabase.
    """

    print(f" Intelligence Agent is searching policies for: {search_terms}")

    found_policies = []

    for term in search_terms:
        vector = embeddings.embed_query(term)

        result = supabase.rpc("match_documents", {
            "query_embedding": vector,
            "match_threshold": 0.3,
            "match_count": 1
        }).execute()

        if result.data:
            for doc in result.data:
                policy_text = f"{doc['content']} (Source: {doc['metadata']['policy_id']})"
                found_policies.append(policy_text)

    unique_policies = list(set(found_policies))

    if not unique_policies:
        print(" No specific policies found. Using Standard Protocal.")
        return ["Policy STD-00: Standard Security Protocol. If behavior is suspicious and no specific exemption exists, BLOCK the request."]

    return unique_policies

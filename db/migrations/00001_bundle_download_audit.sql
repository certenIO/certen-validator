CREATE TABLE public.bundle_downloads (
    download_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_id uuid NOT NULL REFERENCES public.proof_bundles(bundle_id),
    api_key_id uuid REFERENCES public.api_keys(key_id),
    client_ip inet NOT NULL,
    user_agent text NOT NULL,
    response_code integer NOT NULL CHECK (response_code BETWEEN 100 AND 599),
    bytes_sent bigint NOT NULL CHECK (bytes_sent >= 0),
    downloaded_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX bundle_downloads_downloaded_at_idx ON public.bundle_downloads (downloaded_at);
